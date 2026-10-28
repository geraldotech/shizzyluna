# Shizzy Lua.7 — Correção focalizada do parser BPF v2 e APK de validação

**Para:** LLM implementadora Kotlin/Android  
**Repositório:** https://github.com/geraldotech/shizzyluna  
**Base examinada:** `main` no commit `22095b0134736886aeceb7ccf3c4cd1367d5e8ae`  
**Entrada de diagnóstico:** JSON de `parserVersion: 2` fornecido pelo proprietário.  
**Escopo:** correção de parsing, testes, APK `debug` e validação do firewall multi-host. Não publicar diretamente na `main`.

## 1. Evidências reais (não especular)

O relatório da execução contém:

| Campo | Valor |
| --- | ---: |
| Última tentativa | `PARSE_FAILURE` |
| Entradas IPv4 upstream aceitas | 118 |
| Entradas IPv4 downstream aceitas | 121 |
| Linhas rejeitadas | 24 |
| `INCOMPLETE_FLOW_LINE` | 22 |
| `INVALID_AGE` | 2 |
| Snapshot publicado | `false` |
| Mapeamentos ativos | 0 |
| `bpfAttributedPackets` | 0 |
| `unknownForwardedPackets` | 225770 |
| `blockedDropPackets` / `shapedPackets` | 0 / 0 |

Os exemplos rejeitados exibem (endereços mascarados):

```text
udp [xx:xx:xx:xx:xx:xx] 251(251) x.x.x.x:xxxx -> 250(testtun58) x.x.x.x:xxxx -> x.x.x.x:xxxx [xx:xx:xx:xx:xx:xx] 1500 -
tcp [xx:xx:xx:xx:xx:xx] 251(251) x.x.x.x:xxxx -> 250(testtun58) x.x.x.x:xxxx -> x.x.x.x:xxxx [xx:xx:xx:xx:xx:xx] 1500 -3ms
tcp [xx:xx:xx:xx:xx:xx] 250(testtun58) x.x.x.x:xxxx -> 251(251) x.x.x.x:xxxx -> x.x.x.x:xxxx [xx:xx:xx:xx:xx:xx] 1500 -15ms
ifindex (iface) -> ifindex (iface)
```

**Limites da evidência:** 20 rejeições foram exibidas e 4 omitidas. O sufixo `-` parece um marcador de idade ausente, mas sua semântica precisa ser confirmada na implementação real de `dumpsys tethering bpf`. A idade negativa pode resultar de diferença temporal no dump; não presumir que seja idade cronológica do pacote.

## 2. Onde alterar (código confirmado)

Arquivo: `app/src/main/java/dev/shizzi/BpfFlowAttribution.kt`:

- Linha ~193: `IPV4_FLOW_ROW_REGEX`, que atualmente exige `(-?\d+)(ms|s)?` na posição de idade.
- Linhas ~379–411: `isIgnorableSectionLine` não reconhece o cabeçalho com `->`.
- Linhas ~432–540: `parseIpv4FlowLine`, especialmente `ageVal`, `ageUnit` e a rejeição de valores negativos.
- Linhas ~953–980: `NatFlowAttributor.ingestParsedDump` rejeita a publicação inteira se há rejeições e `allowSafePartialPublication` é falso.
- Linhas ~1029–1067: resolução independente de `ifindex` e inferência dos índices a partir de entradas de dump.
- Linhas ~1625+: `BpfMapReader.collectOnce` já preserva o diagnóstico da tentativa.

Arquivo de testes: `app/src/test/java/dev/shizzi/BpfFlowAttributionTest.kt`.

Verificar o código efetivo antes de modificar; os números de linhas são apenas referência do commit citado.

## 3. Alterações exigidas

### A. Cabeçalho de tabela não é fluxo

Reconhecer a linha `ifindex (iface) -> ifindex (iface)` como cabeçalho ignorável **somente por forma estrita** (espaços variáveis e maiúsculas/minúsculas, se necessário). Não ignorar genericamente toda linha que contenha `ifindex` ou `->`, pois isso esconderia dados inválidos.

### B. Representação explícita da idade

Revisar a implementação da fonte Android `dumpsys tethering bpf` antes de definir o significado de `-` e de idades negativas.

- Separar idade *conhecida e não negativa* de idade *não disponível* e de *diferença temporal negativa legítima*, se comprovada.
- Preferir modelo de domínio explícito (`Long?` ou tipo selado, conforme impacto) a converter silenciosamente `-` em `0ms`.
- Se idade negativa for legítima, preservar seu sinal/estado sem deixá-la influenciar incorretamente frescor de snapshot; frescor da coleta já deve usar relógio monotônico local.
- Se idade negativa for realmente dado inválido, manter rejeição com diagnóstico específico.
- Fazer a regex aceitar apenas as representações legitimadas por evidência da implementação Android; não aceitar idade arbitrária ou truncamento do leitor.
- Testar overflow ao converter segundos para milissegundos e preservar cap de bytes e tratamento de truncamento.

### C. Publicação conservadora

- Depois de corrigir os formatos comprovadamente válidos, reexecutar testes antes de considerar publicação parcial.
- **Não ligar** `allowSafePartialPublication` como atalho e não remover `parsed.hasRejections` da política sem revisão de integridade.
- Se ainda restarem linhas desconhecidas, preservar o snapshot anterior enquanto válido, rejeitar a tentativa insegura e exportar motivo detalhado.
- Nunca usar o MAC do hotspot na linha upstream como MAC do cliente; validar binding IP↔MAC, tupla NAT completa, direção reversa e geração da sessão.

### D. Resolução de interface (`ifindex`)

O relatório anterior mostra `swlan0` e `testtun58` com índices independentes `0`, enquanto o dump usa `251` e `250`. Investigar o `interfaceIndexResolver` e suas permissões/visibilidade no Android. Registrar separadamente índice obtido do SO, índice inferido da linha nomeada e motivo de falha da resolução. Não considerar `0` índice real. Não confiar em rótulo numérico isolado nem supor índices estáveis entre sessões. Verificar coerência entre upstream/downstream em cada tupla.

## 4. Testes obrigatórios

Criar testes unitários com dados sintaticamente reais, mas endereços substituídos por endereços de documentação (`192.0.2.0/24`, `198.51.100.0/24`) e MACs fictícios válidos. **Nunca usar os placeholders `x.x.x.x` nos testes do parser**, pois não são IPv4 válidos.

1. Upstream e downstream com idade numérica normal (`230026ms`).
2. Linhas terminadas em `1500 -` de ambas as direções; comportamento de domínio conforme semântica confirmada.
3. Idade `-3ms` e `-15ms`; classificação explícita e sem overflow.
4. Cabeçalho `ifindex (iface) -> ifindex (iface)` ignorado sem rejeição.
5. Uma linha realmente truncada pelo limite do leitor continua fatal.
6. Linha de fluxo faltando campo de endereço/porta/MAC continua rejeitada.
7. Duplicidade de tupla traduzida com clientes diferentes retorna ambígua, sem atribuição incorreta.
8. MAC do hotspot nunca identifica cliente.
9. Alteração de geração e binding invalida atribuição antiga.
10. `ifindex` inferido divergente da direção reversa não valida a associação.
11. Última tentativa e snapshot publicado continuam distinguíveis no JSON/Markdown.
12. Coleção com dados corrigidos publica snapshot **somente se as validações de fluxo e dono forem satisfeitas**.

Executar a suíte disponível e relatar comando, ambiente, resultados e eventuais testes não executados.

## 5. APK obrigatório para o proprietário testar

1. Criar uma branch de trabalho a partir de `main`, sem modificar diretamente a branch principal.
2. Compilar APK **debug** instalável usando Gradle do projeto e SDK Android compatível.
3. Entregar o APK real como artefato descarregável, com nome, SHA-256, `versionCode` e commit de origem. Se não conseguir compilar, fornecer erro exato: nunca afirmar que criou o APK quando não criou.
4. Preservar opções de exportação de diagnóstico; mascarar IPs/MACs por padrão. Não comprometer a chave de assinatura de produção.
5. Não fazer release/publicação automática ou exigir instalação de APK de origem não verificada.

## 6. Protocolo de validação no aparelho: dois hosts

Antes do teste, coletar relatório de uma sessão ativa com clientes conectados e confirmar:

- `lastAttemptStatus` e `lastAttemptSnapshotPublished`;
- rejeições restantes, `totalUpstreamEntries`, `totalDownstreamEntries`, `activeMappedFlows`;
- `downstreamIface`/`upstreamIface` e índices de ambas as fontes;
- `bpfAttributedPackets`, `unknownForwardedPackets`, `blockedDropPackets`, `shapingDropPackets`, `shapedPackets` antes/depois de tráfego.

**Teste operacional:**

1. Conectar os celulares A e B ao hotspot; confirmar que ambos navegam.
2. Iniciar tráfego em ambos, exportar linha de base e identificar qual MAC/IP pertence a cada um.
3. Bloquear **somente A**; verificar perda de acesso em A e manutenção da navegação em B. Medir os contadores de drops.
4. Desbloquear A e confirmar recuperação.
5. Limitar velocidade de A, medir throughput de ambos e verificar os contadores de shaping.
6. Desconectar/reconectar A e conferir atualização de binding sem herdar política de outro cliente.

**Critério crucial:** mapas BPF legíveis não provam que pacotes passam pelo motor de interceptação. Se os mapeamentos forem publicados mas `blockedDropPackets` e `shapedPackets` permanecerem em zero enquanto tráfego prossegue, investigar o caminho real (VPN/TUN vs tethering/offload) **antes de alterar novamente o parser**.

## 7. Critérios de conclusão

- [ ] Causas das 24 rejeições classificadas, incluindo as 4 inicialmente omitidas em novo relatório.
- [ ] Cabeçalho reconhecido sem mascarar erros de fluxos.
- [ ] Semântica de `-` e valores negativos documentada a partir da implementação Android efetiva.
- [ ] Testes de parsing e segurança aprovados.
- [ ] APK debug real entregue, com SHA-256 e referência do commit.
- [ ] Snapshot publicado de forma segura (ou bloqueio remanescente explicado com nova evidência).
- [ ] Índices de interfaces corroborados ou limitação claramente documentada.
- [ ] Em dois celulares reais: bloquear A sem afetar B, desbloquear A e limitar velocidade de A com medidas observadas.

**Não declarar o firewall multi-host concluído apenas porque o parser deixa de rejeitar linhas.**
