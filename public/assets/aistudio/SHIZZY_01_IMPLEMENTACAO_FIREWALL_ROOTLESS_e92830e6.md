# Shizzy Lua — Plano de implementação: BPF v3, atribuição e firewall sem root

**Instrução para a LLM implementadora:** aplique este plano diretamente ao repositório `https://github.com/geraldotech/shizzyluna`, em branch própria, com testes. **Não declare que o firewall funciona até haver comprovação no aparelho.**

**Base examinada:** `main`, commit `29ef77940316acb6b7890fc507f28f22bbbc985e`, `BpfDumpParser.PARSER_VERSION = 3`. Antes de editar, verifique `git status`, HEAD e diffs recentes para preservar mudanças posteriores.

## Objetivo e restrições

Permitir bloqueio e limite de banda **individuais** para clientes Wi-Fi do hotspot usando o proxy TUN da Shizzy e Shizuku iniciado por ADB, **sem root**. O controle de tempo e agenda já existe em `HostFirewall.enforce`; preservar essa lógica. Não criar DHCP próprio, não introduzir um segundo túnel nem reescrever a arquitetura.

**Não usar `iptables`, `ip6tables` ou escrita em `ip rule` como mecanismo necessário no modo sem root.** Diagnóstico real enviado pelo proprietário mostra `Permission denied (you must be root)`, `v4Write=false`, `v6Write=false`, `firstPacketLeak=true`, `datapathMode=USERSPACE_PROXY`. Leitura de `ip route show` não comprova capacidade de escrita.

## Evidências BPF reais

Na execução do parser v3:

- 203 entradas IPv4 upstream e 203 downstream foram aceitas.
- 396 entradas com idade conhecida, 10 com idade indisponível; **nenhuma falha de idade**.
- Quatro linhas não-fluxo foram classificadas como `INCOMPLETE_FLOW_LINE`, levando a `lastAttemptSnapshotPublished=false`:

```text
269 (testtun64) -> 269 (testtun64)
270 (270) -> 270 (270)
26 (rmnet_data0) -> 26 (rmnet_data0)
31 (rmnet_data5) -> 31 (rmnet_data5)
```

- `activeMappedFlows=0`, `bpfAttributedPackets=0`; portanto **ainda não há prova** de atribuição ou bloqueio multi-host.

## Fase 1 — correção mínima do parser (obrigatória)

Arquivos:

- `app/src/main/java/dev/shizzi/BpfFlowAttribution.kt`
- `app/src/test/java/dev/shizzi/BpfFlowAttributionTest.kt`

Em `BpfDumpParser.isIgnorableSectionLine`, já existe `IFINDEX_TABLE_HEADER_REGEX` para o título textual `ifindex (iface) -> ifindex (iface)`. Acrescentar um segundo regex ancorado para **linhas de mapeamento de interfaces sem protocolo nem endpoints**, como:

```kotlin
private val IFINDEX_MAPPING_ROW_REGEX = Regex(
    """^\d+\s*\([^()]+\)\s*->\s*\d+\s*\([^()]+\)$"""
)
```

Reconhecer esse formato em `isIgnorableSectionLine`. Restringir a regra a linhas inteiras; não ignorar qualquer linha que contenha `->`, `ifindex` ou números. Se a saída real revelar outras variantes, registrá-las e testá-las separadamente.

Testes necessários:

1. Uma fixture com 203 pares de fluxos válidos não é necessária; use amostra pequena realista com upstream/downstream e as **quatro linhas exatas** acima. Esperado: zero rejeições, contagem de fluxos preservada.
2. `ifindex (iface) -> ifindex (iface)` continua ignorado.
3. Linhas incompletas com prefixo `tcp` ou `udp` e endpoint ausente continuam rejeitadas.
4. Dump truncado, IP/MAC/porta inválidos e colisões de tuplas continuam protegidos.
5. `ingestParsedDump` publica um snapshot seguro quando há entradas válidas e **nenhuma** rejeição; verificar `lastAttemptSnapshotPublished`, `lastAttemptStatus` e índices.

Não ativar `allowSafePartialPublication` como atalho; mantenha padrão conservador.

## Fase 2 — rootless: separar capacidade de kernel de proxy TUN

Arquivo `HostFirewall.kt`:

- A lógica existente de `probeKernelCapabilities` testa escrita em netfilter e policy routing. No ambiente documentado, isso falhou. Evitar tentativas repetidas de modificar essas estruturas no modo rootless; permitir o diagnóstico **somente leitura** e relatar claramente `USERSPACE`/sem escrita.
- Não fazer `syncKernelRules` depender do sucesso de leitura de comandos. Só habilitar backend de kernel se escrita realmente confirmada num modo explicitamente autorizado. Se remover probes de escrita no fluxo sem root, documentar que a ausência deles **não comprova** tecnicamente ausência universal de capacidade em outros aparelhos.
- Preservar `HostFirewall.enforce`: `rule.isBlocked`, horário `scheduleEnabled`, `connectionTimeLimitMinutes`, `bandwidthLimitKbps`. Essas políticas já são traduzidas para `TunTrafficEngine.EnforcedClientPolicy`.
- Não inserir regras globais de `DROP` por IP NAT compartilhado (`192.0.2.2`), pois isso bloquearia todos os clientes.

## Fase 3 — atribuição segura no proxy TUN (prioridade para regressão de um cliente)

Arquivo `TunTrafficEngine.kt`:

- O `relayUploadLoop`/`relayDownloadLoop` já recebe pacotes e chama `resolveClientMacWithSource` e `evaluateAndShapeDetailed`.
- O resolver tenta IP original → MAC, depois BPF para tupla traduzida completa, depois conntrack procfs, quando disponível.
- Quando `matchedMac == null`, o motor contabiliza `unknownForwardedPackets` e **permite** o pacote. Não substituir cegamente por `DROP` nem associar todo fluxo NAT a um cliente só porque só um host está conectado — a atribuição precisa de prova para evitar interferência em tráfego local ou mudanças de sessão.
- Adicionar testes de regressão com **um único cliente**: IP original visível → MAC validado → política `DROP`; e política de 1 Mbps → decisão de shaping, sem afetar tráfego sem política. Repetir com fluxo pós-NAT **validado** pelo BPF e com fluxo desconhecido; nunca inventar o MAC.
- Garantir que `updatePolicies` não invalida bindings ativos indevidamente, que mudanças de IP/MAC e `sessionGeneration` invalidam fluxos anteriores, e que política alterada é aplicada em pacotes já mapeados.
- Registrar contadores/causas de atribuição sem logar endpoints sensíveis por padrão: `DIRECT_IP`, `BPF_NAT`, `CONNTRACK_PROCFS`, `UNKNOWN`, ambiguidade, `USERSPACE_PROXY` versus `DIRECT_TUN_FALLBACK`.
- Avaliar a janela `firstPacketLeak=true`: o BPF é assíncrono; primeiro pacote pode não ter mapeamento. **Não prometer bloqueio perfeito de primeiro pacote** sem um mecanismo de captura pré-NAT comprovado.

## Fase 4 — validar gateway e interfaces

- `TetherSession` cria o TestNetwork TUN e `SessionResources.startDatapath` usa `TunTrafficEngine.attach`. Confirmar no log que o modo é `USERSPACE_PROXY` durante todo o teste; se houver fallback, explicar.
- `swlan0` é downstream observado e `testtunXX` é upstream observado. Não confundir IP original do cliente com `TUN_LOCAL_V4=192.0.2.2`.
- Validar `ifindex` a partir de fontes independentes quando possível, ou relatar indisponibilidade sem assumir `0` como índice real.

## Critérios de aceitação de código

- [ ] O parser aceita as quatro linhas de mapeamento como metadados e mantém rejeição de fluxos realmente inválidos.
- [ ] Testes unitários novos para cabeçalhos, parsing e cenário de um cliente; teste existente de dois clientes continua passando.
- [ ] Modo rootless não depende de escrita em `iptables`/`ip rule`; nenhum fallback declara bloqueio instalado sem evidência.
- [ ] Políticas de bloqueio, tempo/agenda e banda continuam integradas ao proxy TUN.
- [ ] Identidade desconhecida não é transformada em MAC fictício nem em bloqueio global.
- [ ] Logs/relatórios separam coleta, publicação de mapeamentos, atribuição e decisão de firewall.
- [ ] A LLM entrega branch/PR, SHA do commit, resumo do diff e resultado **real** dos testes. Se faltar SDK/build, relatar a limitação.

## Proibições

Não alterar `main` diretamente. Não introduzir root, `su`, serviço VPN alternativo, DHCP próprio, desativação global de offload, `DROP` indiscriminado de IP traduzido ou logs completos sensíveis por padrão. Não declarar que bloqueio e banda funcionam apenas porque testes unitários passam. Use o documento `SHIZZY_02_BUILD_APK_E_TESTE_REAL.md` para a prova de funcionamento.
