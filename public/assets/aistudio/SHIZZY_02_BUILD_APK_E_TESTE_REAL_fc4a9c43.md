# Shizzy Lua — Build APK e prova real do firewall (sem root)

**Instrução para a LLM de build/teste:** executar **após** a implementação de `SHIZZY_01_IMPLEMENTACAO_FIREWALL_ROOTLESS.md`. Repositório: `https://github.com/geraldotech/shizzyluna`. Não fazer merge automático nem release de produção.

## 1. Verificação do código recebido

1. Fazer checkout da branch/commit produzido pela implementação; registrar SHA completo e `git status` limpo (ou explicar alterações locais).
2. Conferir os diffs em `BpfFlowAttribution.kt`, `BpfFlowAttributionTest.kt`, `HostFirewall.kt`, `TunTrafficEngine.kt` e outros arquivos alterados.
3. Confirmar que a mudança do parser ignora apenas linhas informativas de interface, não fluxos `tcp`/`udp` inválidos.
4. Confirmar que não houve inclusão de `su`, regras globais de `DROP`, desativação não autorizada do firewall Android ou dependência de `iptables` para o caminho sem root.

## 2. Testes e build

- Inspecionar `settings.gradle.kts`, `app/build.gradle.kts` e a versão do Gradle/Android SDK antes de escolher o comando.
- Executar testes unitários do módulo Android, preferencialmente `./gradlew :app:testDebugUnitTest` quando a variante existir.
- Compilar APK de diagnóstico `debug` com `./gradlew :app:assembleDebug` quando suportado.
- Se não houver `gradlew` ou a configuração tiver variantes distintas, usar o comando equivalente **efetivamente previsto no projeto**; não inventar sucesso.
- Relatar erros, warnings relevantes, número de testes aprovados/falhos/ignorados e eventual impedimento de ambiente.
- Entregar APK **real** como artefato para download, não apenas um caminho textual. Informar arquivo, tamanho, SHA-256 (`sha256sum`), `applicationId`, `versionCode`/`versionName`, commit e eventual conflito de assinatura com APK já instalado.
- Não usar chave de upload de produção nem publicar release automaticamente.

## 3. Preparação do teste no Galaxy

Usar o aparelho que fornece hotspot e Shizuku via ADB **sem root**. Manter as demais configurações constantes entre testes. O usuário executará as ações no dispositivo.

1. Confirmar conexão Shizuku ativa e permissões que a Shizzy usa.
2. Ativar a VPN que o hotspot deve compartilhar, iniciar a sessão Shizzy e confirmar `datapathMode=USERSPACE_PROXY`.
3. Primeiro testar com **um único celular** conectado. Depois repetir com dois.
4. Não usar o `Pause sharing` nativo da Samsung como indicador de sucesso; nos testes anteriores ele foi contornado pelo roteamento com VPN.
5. Manter aceleração de tethering na mesma configuração em cada comparação; se testar ativado vs desativado, registrar ambas as condições separadamente.

## 4. Roteiro de testes observáveis

### Teste A — parser e atribuição

- Com um cliente gerando tráfego TCP e UDP por pelo menos 30–60 segundos, exportar JSON/Markdown BPF.
- Esperado para confirmar o parser: `lastAttemptStatus=OK` ou estado de coleta válida, `lastAttemptSnapshotPublished=true`, rejeições conhecidas de mapeamento de interfaces iguais a zero.
- Esperado para avançar no firewall: `activeMappedFlows>0` e `bpfAttributedPackets` crescendo **durante tráfego real**. O número de entradas aceitas isoladamente não basta.
- Se o snapshot for publicado mas `activeMappedFlows=0`, investigar `unverifiedOwnerEntries`, binding IP/MAC, índices de interfaces e direção reversa; não continuar mudando regex sem evidência.

### Teste B — um cliente, bloqueio

1. Cliente A navega normalmente. Registrar contadores iniciais.
2. Ativar bloqueio de A pela Shizzy.
3. Iniciar **novas** conexões TCP/UDP e tentar acessar internet; não considerar apenas sessões abertas/cache do navegador.
4. Confirmar se a navegação de A realmente falha e se `blockedDropPackets`/contadores por MAC crescem. Se crescem mas internet continua, investigar rotas que bypassam proxy, IPv6, offload e direção do fluxo.
5. Desbloquear e confirmar recuperação.

### Teste C — um cliente, velocidade

1. Medir velocidade de A sem limite, registrando método e resultado.
2. Aplicar limite conhecido, por exemplo 1 Mbps; testar upload e download separadamente por 30–60 segundos.
3. Confirmar redução de throughput e aumento de `shapedPackets`/`shapingDropPackets` conforme a implementação. Não confundir limite em Kbps com KB/s.
4. Desativar limite e confirmar recuperação.

### Teste D — dois clientes, isolamento

1. Clientes A e B conectados e navegando. Registrar MAC/IP originais verificados.
2. Bloquear A; B deve continuar navegando. Reverter e testar bloqueio de B, com A livre.
3. Aplicar limite de banda somente em A; medir A e B separadamente.
4. Desconectar/reconectar um cliente e confirmar que IP/MAC reassociados não herdam política de outro.
5. Registrar `unknownForwardedPackets` e `ambiguousOrStaleLookups` antes/depois; tráfego desconhecido não demonstra bloqueio individual.

### Teste E — primeiros pacotes e tempo

- Verificar regra de agenda e `connectionTimeLimitMinutes` já existentes, incluindo expiração com fluxo ativo.
- Iniciar conexão inédita de cliente bloqueado; verificar vazamento de primeiro pacote. O diagnóstico anterior mostrou `firstPacketLeak=true`, portanto **não marcar bloqueio completo como aprovado** se persistir.

## 5. Interpretação objetiva

| Resultado | Diagnóstico seguinte |
| --- | --- |
| `PARSE_FAILURE` por interface mapping row | Corrigir reconhecimento estrito de linha informativa; não mexer no motor |
| `snapshotPublished=true`, `activeMappedFlows=0` | Resolver validação IP/MAC/ifindex/reverse-map |
| `activeMappedFlows>0`, `bpfAttributedPackets=0` | Conferir tupla NAT versus pacotes TUN e proxy ativo |
| `bpfAttributedPackets>0`, drops crescem, mas internet funciona | Investigar bypass/IPv6/offload, não presumir sucesso |
| Drops funcionam, velocidade não | Investigar token bucket, pacing e direção upload/download |
| A bloqueado e B também afetado | Falha grave de isolamento: parar rollout e revisar atribuição/política |
| `firstPacketLeak=true` | Limitação de atribuição assíncrona ainda aberta; exigir solução comprovada ou declarar parcial |

## 6. Relatório final obrigatório

Entregar ao proprietário um relatório com:

```text
Commit testado:
APK / SHA-256 / versão:
Dispositivo / Android / Shizuku:
Modo datapath / downstream / upstream:
Testes unitários: aprovado/falho/não executado
Parser publicado? Entradas? Rejeições?
Mapeamentos ativos / BPF-attributed / desconhecidos:
Cliente A: bloqueio, desbloqueio, 1 Mbps, tempo
Cliente B: navegação preservada, velocidade
Primeiro pacote: vazamento sim/não/não medido
IPv4 / IPv6 / TCP / UDP: cobertura observada
Conclusão: FUNCIONAL / PARCIAL / NÃO FUNCIONAL
Falhas remanescentes + evidências:
```

**Nunca declarar “funcional” só porque o APK compila ou `lastAttemptSnapshotPublished=true`.** O critério final é bloquear A sem afetar B, limitar a banda de A com medida de throughput e registrar limitações de primeiro pacote e IPv6. Preserve a `main` até revisão e aprovação do proprietário.
