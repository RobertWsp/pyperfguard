"""Simulação 5 — Impacto real em produção: análise consolidada dos 3 padrões

Estima o impacto real em produção baseado nos padrões detectados no CRM,
considerando volume de tráfego típico de um SaaS B2B.
"""

from __future__ import annotations

import asyncio
import statistics
import time
from uuid import uuid4


# ---------------------------------------------------------------------------
# Premissas de tráfego (estimativas conservadoras CRM B2B)
# ---------------------------------------------------------------------------

TRAFFIC = {
    # Grupo WhatsApp sendo criado/atualizado
    "group_resolve_phones": {
        "rpm": 20,               # 20 requests/min (grupos criados)
        "avg_group_size": 30,    # média de 30 participantes
        "p50_latency_n1": 75.0,  # ms (30 participantes * 2.5ms)
        "p50_latency_fix": 2.5,  # ms (1 batch query)
        "pattern": "group_helpers.py:84",
        "rule": "PKN102",
    },
    # Cleanup task de attendance expirada
    "cleanup_attendance": {
        "rpm": 2,                # roda a cada 30s = 2/min
        "avg_expired": 25,       # média de 25 conversas expiradas por run
        "p50_latency_n1": 275.0, # ms (25 * 11ms)
        "p50_latency_fix": 200.0, # ms (LWT sequencial inevitável, DELETEs em batch)
        "pattern": "tasks.py:193",
        "rule": "PKN102",
    },
    # Close inactive conversations (loop de 3 statuses)
    "close_inactive": {
        "rpm": 2,                # roda a cada 30s
        "avg_companies": 10,     # 10 empresas ativas
        "p50_latency_n1": 75.0,  # ms (3 queries * 2.5ms * 10 empresas)
        "p50_latency_fix": 45.0, # ms (gather, empresas ainda sequenciais)
        "pattern": "tasks.py:683",
        "rule": "PKN102",
    },
}


def _print_impact_table() -> None:
    print("=" * 80)
    print("ESTIMATIVA DE IMPACTO EM PRODUÇÃO — Padrões N+1 Detectados no CRM")
    print("=" * 80)
    print()
    print(f"{'Padrão':<30} {'RPM':>6} {'Latência N+1':>14} {'Latência Fix':>14} {'Speedup':>9}")
    print("-" * 75)

    for name, t in TRAFFIC.items():
        n1_ms = t["p50_latency_n1"]
        fix_ms = t["p50_latency_fix"]
        speedup = n1_ms / fix_ms if fix_ms > 0 else 0
        rpm = t["rpm"]
        print(
            f"{t['pattern']:<30} {rpm:>6} {n1_ms:>13.1f}ms {fix_ms:>13.1f}ms {speedup:>8.1f}x"
        )

    print()
    print("ESTIMATIVA DE MELHORIA (por hora de produção):")
    print()

    for name, t in TRAFFIC.items():
        rpm = t["rpm"]
        n1_ms = t["p50_latency_n1"]
        fix_ms = t["p50_latency_fix"]
        calls_per_hour = rpm * 60

        time_wasted_sec = (n1_ms - fix_ms) * calls_per_hour / 1000
        queries_saved = 0

        if name == "group_resolve_phones":
            queries_saved = (t["avg_group_size"] - 1) * calls_per_hour
        elif name == "cleanup_attendance":
            queries_saved = (t["avg_expired"] * 2) * calls_per_hour
        elif name == "close_inactive":
            # gather não reduz queries, apenas paraleliza
            queries_saved = 0

        print(f"  {t['pattern']}:")
        print(f"    Chamadas/hora:        {calls_per_hour:,}")
        print(f"    Latência desperdiçada: {time_wasted_sec:.0f}s/hora de event loop")
        if queries_saved > 0:
            print(f"    Queries economizadas:  {queries_saved:,}/hora")
        print()


async def _run_fastapi_simulation() -> None:
    """Simula o comportamento do PyperfguardMiddleware em uma requisição."""
    from pyperfguard.runtime_engine.scope import Scope, set_scope, reset_scope
    from pyperfguard.detectors.execution_graph import ExecutionGraphN1Detector
    from pyperfguard.runtime_engine.events import QueryEvent

    print("DEMONSTRAÇÃO: PyperfguardMiddleware interceptando a request")
    print()

    # Simula middleware criando o scope
    scope = Scope(name="POST /conversations/group")
    token = set_scope(scope)

    try:
        # Simula N+1 durante a request (como o patcher Cassandra faria)
        contact_ids = [uuid4() for _ in range(8)]
        company_id = uuid4()

        STACK = (
            "src/core/executor.py:45 in execute",
            "src/messaging/group_helpers.py:41 in _get_contact_phone",
            "src/messaging/group_helpers.py:84 in resolve_group_participant_phones",
            "src/messaging/service.py:892 in create_group",
            "src/messaging/router.py:450 in create_group_endpoint",
        )

        import hashlib
        fp = hashlib.md5(b"SELECT phone FROM contacts_by_id").hexdigest()[:8]

        t_start = time.perf_counter()
        for cid in contact_ids:
            await asyncio.sleep(0.002)  # 2ms por query
            scope.record(QueryEvent(
                fingerprint=fp,
                db_system="cassandra",
                statement="SELECT phone FROM contacts_by_id WHERE id = %s",
                duration_s=0.002,
                call_site=hash(STACK),
                stack_frames=STACK,
            ))
        request_time_ms = (time.perf_counter() - t_start) * 1000

    finally:
        reset_scope(token)

    # Middleware avalia o scope após o request
    detector = ExecutionGraphN1Detector(threshold=3)
    findings = detector.evaluate(scope)

    print(f"  Request: POST /conversations/group")
    print(f"  Tempo total: {request_time_ms:.1f}ms")
    print(f"  Queries Cassandra: {scope.event_count()}")
    print(f"  PKN101 findings: {len(findings)}")
    print()

    for f in findings:
        print(f"  ⚠ [{f.rule_id}] N+1 detectado em runtime!")
        print(f"    Query:   {f.extra['statement'][:60]}")
        print(f"    Vezes:   {f.extra['count']}×")
        print(f"    Total:   {f.extra['total_ms']:.1f}ms (de {request_time_ms:.1f}ms)")
        print(f"    % tempo: {f.extra['total_ms']/request_time_ms*100:.0f}% do request gasto em N+1")
        print()
        print(f"    Cadeia de execução:")
        for frame in reversed(f.stack[:5]):
            func = frame.rsplit(" in ", 1)[-1]
            file_line = frame.rsplit(" in ", 1)[0]
            print(f"      {file_line} → {func}")

    print()
    print("  Como usar no seu projeto:")
    print()
    print("  # main.py")
    print("  from pyperfguard.integrations.fastapi import PyperfguardMiddleware")
    print("  from pyperfguard.detectors.execution_graph import ExecutionGraphN1Detector")
    print()
    print("  app.add_middleware(")
    print("      PyperfguardMiddleware,")
    print("      detectors=[ExecutionGraphN1Detector(threshold=3)],")
    print("      on_findings=lambda findings, req: logger.warning(")
    print("          'n1_detected',")
    print("          path=req['path'],")
    print("          count=len(findings),")
    print("      ),")
    print("  )")


async def main() -> None:
    _print_impact_table()
    print()
    print("=" * 80)
    print("DEMONSTRAÇÃO DO MIDDLEWARE EM AÇÃO")
    print("=" * 80)
    print()
    await _run_fastapi_simulation()

    print("=" * 80)
    print("RESUMO FINAL — O que o pyperfguard faz por você:")
    print()
    print("  PKN101 (Runtime — Execution Graph):")
    print("    ✓ Zero configuração — só add_middleware()")
    print("    ✓ Detecta N+1 em qualquer profundidade de call stack")
    print("    ✓ Stack trace exato aponta onde está o loop")
    print("    ✓ Zero falsos positivos — só reporta o que realmente aconteceu")
    print()
    print("  PKN102 (Static — Call Graph):")
    print("    ✓ Sem rodar o código — analisa todo o projeto de uma vez")
    print("    ✓ Detecta cross-function N+1 (router → service → helper → DB)")
    print("    ✓ Funciona em CI/CD antes do deploy")
    print("    ⚠ Alguns falsos positivos (LWT loops, small-N loops)")
    print()
    print("  Combinados: runtime captura o que estático falha, estático")
    print("  detecta em CI antes de chegar em produção.")


if __name__ == "__main__":
    asyncio.run(main())
