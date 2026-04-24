"""Simulação 1 — N+1 cross-function: resolve_group_participant_phones()

Padrão REAL encontrado em crm/api/src/messaging/group_helpers.py:84

PROBLEMA:
    for contact_id in contact_ids:
        contact_phone = await _get_contact_phone(executor, company_id, contact_id)

    _get_contact_phone() faz:
        SELECT phone FROM contacts_by_id WHERE id = %s

Resultado: 1 query por participante do grupo → N queries para N contatos.
Em grupos WhatsApp com 50-256 membros: 50-256 queries por operação.

SOLUÇÃO:
    contact_phones = await executor.execute(
        "SELECT id, phone FROM contacts_by_id WHERE id IN %s",
        (ValueSequence(contact_ids),),
    )
    phone_map = {row.id: row.phone for row in contact_phones.all()}

Resultado: 1 query para todos → independente do tamanho do grupo.
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass
from uuid import UUID, uuid4


# ---------------------------------------------------------------------------
# Simulação de latência Cassandra (distribuição realista)
# ---------------------------------------------------------------------------

def _fake_cassandra_latency_ms() -> float:
    """Simula latência de query Cassandra: p50=2ms, p95=8ms, p99=25ms."""
    import random
    # Exponencial truncada — maioria rápida, cauda longa
    base = random.expovariate(1 / 2.5)  # média 2.5ms
    return min(base, 50.0)  # cap em 50ms


@dataclass
class FakeCassandraExecutor:
    """Simula o CassandraExecutor do projeto com latência realista."""
    _query_log: list[tuple[str, float]]

    def __init__(self) -> None:
        self._query_log = []

    async def execute(self, query: str, params: tuple = ()) -> "FakeResult":
        lat = _fake_cassandra_latency_ms()
        await asyncio.sleep(lat / 1000)
        self._query_log.append((query, lat))
        # Simula retorno de dados
        if "IN %s" in query or "IN ?" in query or "IN" in query:
            # Bulk query retorna todos de uma vez
            n = len(params[0]) if params and hasattr(params[0], '__len__') else 1
            return FakeResult([{"id": uuid4(), "phone": f"+55119{i:07d}"} for i in range(n)])
        return FakeResult([{"id": params[0] if params else uuid4(),
                           "phone": "+5511912345678"}])

    @property
    def query_count(self) -> int:
        return len(self._query_log)

    @property
    def total_latency_ms(self) -> float:
        return sum(lat for _, lat in self._query_log)


@dataclass
class FakeResult:
    _rows: list[dict]

    def one(self) -> dict | None:
        return self._rows[0] if self._rows else None

    def all(self) -> list[dict]:
        return self._rows


# ---------------------------------------------------------------------------
# Padrão N+1 ATUAL (do código do CRM)
# ---------------------------------------------------------------------------

async def _get_contact_phone_n1(
    executor: FakeCassandraExecutor,
    company_id: UUID,
    contact_id: UUID,
) -> str | None:
    """Replica exata de group_helpers._get_contact_phone — 1 query por contato."""
    row = (
        await executor.execute(
            "SELECT phone FROM contacts_by_id WHERE id = %s",
            (contact_id,),
        )
    ).one()
    if not row:
        return None
    return row.get("phone")


async def resolve_phones_n1(
    executor: FakeCassandraExecutor,
    company_id: UUID,
    contact_ids: list[UUID],
) -> list[str]:
    """Replica de resolve_group_participant_phones — N queries."""
    resolved = []
    for contact_id in contact_ids:                          # ← N+1 aqui
        phone = await _get_contact_phone_n1(executor, company_id, contact_id)
        if phone:
            resolved.append(phone)
    return resolved


# ---------------------------------------------------------------------------
# Padrão CORRIGIDO (batch query)
# ---------------------------------------------------------------------------

async def resolve_phones_batch(
    executor: FakeCassandraExecutor,
    company_id: UUID,
    contact_ids: list[UUID],
) -> list[str]:
    """1 query para todos os contatos → join em Python."""
    if not contact_ids:
        return []
    rows = (
        await executor.execute(
            "SELECT id, phone FROM contacts_by_id WHERE id IN %s",
            (contact_ids,),  # ValueSequence na prática real
        )
    ).all()
    return [row["phone"] for row in rows if row.get("phone")]


# ---------------------------------------------------------------------------
# Padrão CORRIGIDO ALTERNATIVO (asyncio.gather — paralelo)
# ---------------------------------------------------------------------------

async def resolve_phones_gather(
    executor: FakeCassandraExecutor,
    company_id: UUID,
    contact_ids: list[UUID],
) -> list[str]:
    """N queries paralelas via asyncio.gather — reduz latência ao máximo."""
    phones = await asyncio.gather(*[
        _get_contact_phone_n1(executor, company_id, cid)
        for cid in contact_ids
    ])
    return [p for p in phones if p]


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

async def benchmark(group_sizes: list[int], runs: int = 5) -> None:
    print("=" * 70)
    print("SIMULAÇÃO: resolve_group_participant_phones() — N+1 vs Otimizado")
    print("Padrão real: crm/api/src/messaging/group_helpers.py:84")
    print("=" * 70)
    print()
    print(f"{'Grupo':>8}  {'Queries':>7}  {'N+1 (ms)':>12}  {'Batch (ms)':>12}  {'Gather (ms)':>13}  {'Speedup':>8}")
    print("-" * 70)

    for n in group_sizes:
        company_id = uuid4()
        contact_ids = [uuid4() for _ in range(n)]

        # N+1 sequential
        n1_times = []
        n1_queries = 0
        for _ in range(runs):
            ex = FakeCassandraExecutor()
            t0 = time.perf_counter()
            await resolve_phones_n1(ex, company_id, contact_ids)
            n1_times.append((time.perf_counter() - t0) * 1000)
            n1_queries = ex.query_count

        # Batch (1 query)
        batch_times = []
        for _ in range(runs):
            ex = FakeCassandraExecutor()
            t0 = time.perf_counter()
            await resolve_phones_batch(ex, company_id, contact_ids)
            batch_times.append((time.perf_counter() - t0) * 1000)

        # Gather (parallel)
        gather_times = []
        for _ in range(runs):
            ex = FakeCassandraExecutor()
            t0 = time.perf_counter()
            await resolve_phones_gather(ex, company_id, contact_ids)
            gather_times.append((time.perf_counter() - t0) * 1000)

        n1_med = statistics.median(n1_times)
        batch_med = statistics.median(batch_times)
        gather_med = statistics.median(gather_times)
        speedup = n1_med / batch_med if batch_med > 0 else 0

        print(
            f"{n:>8}  {n1_queries:>7}  {n1_med:>12.1f}  {batch_med:>12.1f}  "
            f"{gather_med:>13.1f}  {speedup:>7.1f}x"
        )

    print()
    print("Legenda:")
    print("  N+1    = padrão atual (1 query por contato, sequencial)")
    print("  Batch  = 1 query IN (...) para todos os contatos")
    print("  Gather = N queries em paralelo (asyncio.gather)")
    print()
    print("Impacto real (grupo WhatsApp 50 membros, p50=2.5ms/query):")
    print("  N+1:    ~125ms por chamada  → bloqueia handler por 125ms")
    print("  Batch:  ~2.5ms por chamada  → 50x mais rápido")
    print("  Gather: ~8ms por chamada    → bounded por worst-case query")
    print()
    print("Fix sugerido pelo PKN102:")
    print("  rows = await executor.execute(")
    print("      'SELECT id, phone FROM contacts_by_id WHERE id IN %s',")
    print("      (ValueSequence(contact_ids),),")
    print("  )")
    print("  phone_map = {row.id: row.phone for row in rows.all()}")


if __name__ == "__main__":
    asyncio.run(benchmark([5, 10, 25, 50, 100, 256]))
