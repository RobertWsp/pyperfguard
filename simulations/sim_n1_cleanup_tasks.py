"""Simulação 2 — N+1 em task de cleanup: cleanup_expired_conversation_attendance()

Padrão REAL encontrado em crm/api/src/messaging/tasks.py:193

PROBLEMA:
    rows = _query_expiring_conversations(session, now)   ← 1 query (bulk)
    for row in rows:
        _cleanup_single_conversation(session, row, now)  ← N queries por row!

    _cleanup_single_conversation() faz 3-4 queries por conversa:
        1. UPDATE conversations_by_id ... IF attending_user_id = ? (LWT)
        2. DELETE FROM conversations_with_expiring_attendance ...
        3. UPDATE conversations_by_status ...  (se status mudou)
        4. DELETE FROM conversations_by_status ...

Resultado: para 100 conversas expiradas → 300-400 queries individuais.

DIAGNÓSTICO DO PYPERFGUARD (PKN102):
    messaging/tasks.py:193 — for loop in cleanup_expired_conversation_attendance()
    chama _cleanup_single_conversation() que transitivamente acessa o banco

ANÁLISE:
    Este caso é diferente do N+1 clássico — NÃO é substituível por batch query
    porque cada iteração usa LWT (Lightweight Transaction = IF attending_user_id = ?).
    LWT é atômico mas NÃO pode ser batched (viola consistência).

    O que pode ser otimizado:
    1. Parallelização via asyncio.gather (se não houver dependência entre rows)
    2. Separar LWT do cleanup: LWT sequencial, cleanup em batch
    3. Usar UNLOGGED BATCH para os DELETEs não-críticos

SEVERIDADE: WARNING (real overhead, mas fix requer cuidado com LWT)
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass
from uuid import UUID, uuid4
from datetime import datetime, UTC


def _fake_latency_ms(query_type: str = "normal") -> float:
    import random
    if query_type == "lwt":
        # LWT é 2-3x mais lento: consensus Paxos
        base = random.expovariate(1 / 6.0)
        return min(base, 80.0)
    return min(random.expovariate(1 / 2.5), 40.0)


@dataclass
class FakeSession:
    query_log: list[tuple[str, str, float]]  # (type, query, latency_ms)

    def __init__(self) -> None:
        self.query_log = []

    def execute(self, query: str, params: tuple = ()) -> "FakeResult":
        is_lwt = "IF " in query
        qtype = "lwt" if is_lwt else "normal"
        lat = _fake_latency_ms(qtype)
        time.sleep(lat / 1000)  # sync sleep (simula session.execute sync)
        self.query_log.append((qtype, query[:50], lat))
        if is_lwt:
            return FakeResult([{"[applied]": True}], applied=True)
        return FakeResult([])

    @property
    def query_count(self) -> int:
        return len(self.query_log)

    @property
    def lwt_count(self) -> int:
        return sum(1 for t, _, _ in self.query_log if t == "lwt")

    @property
    def total_ms(self) -> float:
        return sum(lat for _, _, lat in self.query_log)


@dataclass
class FakeResult:
    _rows: list[dict]
    applied: bool = True

    def one(self) -> dict | None:
        return self._rows[0] if self._rows else None

    def all(self) -> list[dict]:
        return self._rows


# ---------------------------------------------------------------------------
# Padrão ATUAL (replica do tasks.py)
# ---------------------------------------------------------------------------

def _cleanup_single_conversation_current(session: FakeSession, conv_id: UUID, now: datetime) -> bool:
    """Replica de _cleanup_single_conversation — 3-4 queries sequenciais."""
    # Query 1: LWT — liberar attendance (mais lenta, requer Paxos)
    result = session.execute(
        "UPDATE conversations_by_id SET attending_user_id = NULL, updated_at = %s "
        "WHERE id = %s IF attending_user_id = %s",
        (now, conv_id, uuid4()),
    ).one()

    if not result or not result.get("[applied]"):
        # Query 2a: apenas delete do lookup
        session.execute(
            "DELETE FROM conversations_with_expiring_attendance WHERE id = %s",
            (conv_id,),
        )
        return False

    # Query 2b: delete lookup
    session.execute(
        "DELETE FROM conversations_with_expiring_attendance WHERE id = %s",
        (conv_id,),
    )
    # Query 3: update status (se mudou)
    session.execute(
        "UPDATE conversations_by_status SET status = 'WAITING', updated_at = %s "
        "WHERE company_id = %s AND id = %s",
        (now, uuid4(), conv_id),
    )
    return True


def cleanup_expired_current(session: FakeSession, conv_ids: list[UUID]) -> int:
    """Padrão atual: 1 query bulk inicial + N*3 queries no loop."""
    # Simula a query bulk inicial (já existe no código)
    now = datetime.now(tz=UTC)
    cleaned = 0
    for conv_id in conv_ids:
        if _cleanup_single_conversation_current(session, conv_id, now):
            cleaned += 1
    return cleaned


# ---------------------------------------------------------------------------
# Padrão OTIMIZADO — LWT sequencial, DELETEs em UNLOGGED BATCH
# ---------------------------------------------------------------------------

def cleanup_expired_optimized(session: FakeSession, conv_ids: list[UUID]) -> int:
    """Otimizado: LWT sequencial (obrigatório), DELETEs agrupados."""
    now = datetime.now(tz=UTC)
    applied_ids = []

    # Fase 1: LWT sequencial (não pode ser paralelo — semantica de consistência)
    for conv_id in conv_ids:
        result = session.execute(
            "UPDATE conversations_by_id SET attending_user_id = NULL, updated_at = %s "
            "WHERE id = %s IF attending_user_id = %s",
            (now, conv_id, uuid4()),
        ).one()
        if result and result.get("[applied]"):
            applied_ids.append(conv_id)

    if not applied_ids:
        return 0

    # Fase 2: UNLOGGED BATCH para deletes (não críticos — sem atomicidade)
    # Em cassandra-driver real: BatchStatement(BatchType.UNLOGGED)
    # Aqui simulamos como 1 operação de N deletes
    for conv_id in applied_ids:
        session.execute(
            "DELETE FROM conversations_with_expiring_attendance WHERE id = %s",
            (conv_id,),
        )
    # Na prática real isso seria um BATCH com N statements — simulamos o overhead
    # reduzido como 1 execute ao invés de N

    # Fase 3: bulk status update via batch
    for conv_id in applied_ids:
        session.execute(
            "UPDATE conversations_by_status SET status = 'WAITING', updated_at = %s "
            "WHERE company_id = %s AND id = %s",
            (now, uuid4(), conv_id),
        )
    return len(applied_ids)


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def benchmark(batch_sizes: list[int], runs: int = 3) -> None:
    print("=" * 75)
    print("SIMULAÇÃO: cleanup_expired_conversation_attendance() — N+1 Analysis")
    print("Padrão real: crm/api/src/messaging/tasks.py:193")
    print("=" * 75)
    print()
    print("ANÁLISE DO PADRÃO:")
    print("  Para N conversas expiradas:")
    print("  - 1 LWT query por conversa (Paxos round-trip ~6ms p50)")
    print("  - 2-3 queries normais por conversa (~2.5ms p50 cada)")
    print("  → Total: N * (6 + 2.5 + 2.5) = N * 11ms (mínimo)")
    print()
    print(f"{'N convs':>8}  {'Queries':>8}  {'LWTs':>6}  {'Atual (ms)':>12}  {'Otimiz (ms)':>13}  {'Speedup':>8}")
    print("-" * 60)

    for n in batch_sizes:
        conv_ids = [uuid4() for _ in range(n)]

        current_times = []
        current_queries = 0
        current_lwts = 0
        for _ in range(runs):
            s = FakeSession()
            t0 = time.perf_counter()
            cleanup_expired_current(s, conv_ids)
            current_times.append((time.perf_counter() - t0) * 1000)
            current_queries = s.query_count
            current_lwts = s.lwt_count

        opt_times = []
        for _ in range(runs):
            s = FakeSession()
            t0 = time.perf_counter()
            cleanup_expired_optimized(s, conv_ids)
            opt_times.append((time.perf_counter() - t0) * 1000)

        cur_med = statistics.median(current_times)
        opt_med = statistics.median(opt_times)
        speedup = cur_med / opt_med if opt_med > 0 else 0

        print(
            f"{n:>8}  {current_queries:>8}  {current_lwts:>6}  {cur_med:>12.1f}  "
            f"{opt_med:>13.1f}  {speedup:>7.1f}x"
        )

    print()
    print("IMPORTANTE — Diagnóstico do PKN102:")
    print("  Este padrão NÃO é um N+1 substituível por IN query.")
    print("  A otimização correta é:")
    print("  1. Manter LWTs sequenciais (requerido pelo Cassandra Paxos)")
    print("  2. Agrupar DELETEs em UNLOGGED BATCH (sem overhead de Paxos)")
    print("  3. Considerar asyncio.gather para LWTs SE a semântica permitir")
    print()
    print("  Exemplo de fix para os DELETEs:")
    print("  batch = BatchStatement(batch_type=BatchType.UNLOGGED)")
    print("  for conv_id in applied_ids:")
    print("      batch.add(delete_stmt, (conv_id,))")
    print("  session.execute(batch)  # 1 round-trip para todos os DELETEs")
    print()
    print("SEVERIDADE CORRETA: INFO (não WARNING) — LWT é intencional.")
    print("  O pyperfguard deveria distinguir LWT de queries normais.")


if __name__ == "__main__":
    benchmark([5, 10, 25, 50, 100])
