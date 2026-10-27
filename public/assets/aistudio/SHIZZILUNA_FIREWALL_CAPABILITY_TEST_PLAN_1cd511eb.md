# ShizziLuna — Teste de capacidade do firewall por cliente via Shizuku

## Objetivo desta tarefa

Implementar um modo de diagnóstico e uma prova de conceito controlada para descobrir qual mecanismo realmente funciona neste aparelho:

1. **Filtragem no encaminhamento, com identidade original do cliente disponível**, antes da tradução de saída esconder seu IP.
2. **Filtragem no TUN com mapeamento conntrack**, se o primeiro mecanismo não estiver disponível.

O resultado esperado é: **cliente A continua associado ao Wi-Fi, mas sem acesso à internet pelo hotspot; cliente B continua associado e navegando normalmente**. Ao desbloquear A, sua internet deve voltar sem reiniciar o hotspot.

Esta tarefa é de diagnóstico e validação. Não declarar o firewall corrigido apenas por compilar o APK ou passar em testes unitários. Não implementar bloqueio por desconexão do Wi-Fi como substituição silenciosa.

## Base e contexto já verificados

- Repositório atual: https://github.com/geraldotech/shizzyluna
- Revisão anteriormente analisada: `0b0d7595ffc5605b3582bd639c3f7ff14cbd10e2`.
- Versão declarada nessa revisão: `0.4.0-rs-lua4`, versionCode `9`.
- Repositório anterior: https://github.com/geraldotech/shizzylua
- Revisão anterior: `0cc882c7d7e7aa55e4b3bcf970be2f3912e03c45`.
- Documento anterior: `SHIZZILUA_MULTI_CLIENT_FIREWALL_FIX.md`.

Antes de implementar, ler as instruções do repositório e verificar o HEAD atual. Registrar o SHA usado no diagnóstico. Os achados abaixo referem-se à revisão analisada, não a possíveis commits posteriores.

### Evidência do aparelho

O usuário informou que o cliente configurado como bloqueado continua navegando. Um screenshot de log mostrou:

```text
Traffic: direction=UPLOAD src=192.0.2.2 dst=64.233.190.188
matchedMac=none decision=ALLOW

Traffic: direction=DOWNLOAD src=172.217.29.46 dst=192.0.2.2
matchedMac=none decision=ALLOW

Traffic: direction=UPLOAD src=192.0.2.2 dst=8.8.8.8
matchedMac=none decision=ALLOW
```

Também havia 41 pacotes identificados e descartados para um MAC. Isso não prova bloqueio completo. O screenshot não permite atribuir os pacotes não identificados àquele mesmo cliente, nem prova que conntrack estava inacessível.

Havia tráfego IPv6 `fe80::... -> ff02::2`: não tratar esse tráfego local de controle como prova de navegação liberada.

O log também registrou substituição de VPN e saída do tethering de `testtun38`, seguida de encerramento da sessão. Esses eventos devem ser correlacionados com o teste; não presumir que a ausência momentânea da VPN, sozinha, explica todos os descartes ou o encerramento.

### Achados no código analisado

- `TunTrafficEngine.evaluateAndShape()` libera pacotes quando `matchedMac == null`.
- O atalho `singleActiveClientMac` foi removido. Ele não era identificação multicliente confiável e não deve ser restaurado como solução geral.
- O caminho pós-NAT depende do cache de fluxos e de leituras de conntrack.
- `HostFirewall` considera `ip rule show` bem-sucedido como evidência de capacidade do kernel. **Listar regras não comprova poder de modificá-las ou aplicar um bloqueio.**
- `Blocked (verified)` ainda pode decorrer de contadores acumulados.
- Testes de atribuição injetam linhas sintéticas de conntrack; não validam a obtenção desses dados no telefone.

## Restrições e critérios técnicos

- O alvo inicial é **Shizuku iniciado por ADB, sem depender de root**. Registrar o modo real encontrado.
- Uma API privilegiada só é candidata se a operação específica for permitida ao UID, contexto SELinux e capacidades reais do processo.
- Não confundir permissão Android para controlar o hotspot com capacidade Linux para modificar netfilter, rotas ou acessar conntrack.
- Manter políticas por MAC normalizado e bindings atuais de IPv4/IPv6. MAC é a identidade observada naquela associação, não uma identidade imutável contra randomização.
- Um cliente pode estar associado antes de receber IPv4 e pode possuir vários IPv6. Não fixar IPs de exemplos, interface `swlan0` ou nome `testtun38`.
- Não trocar globalmente `ALLOW` por `DROP` para tráfego desconhecido: isso pode bloquear B. Se não houver atribuição seletiva, reportar indisponibilidade.
- Não limpar tabelas globais, alterar políticas padrão, desativar SELinux ou executar comandos `su` automaticamente neste teste sem root.
- Não alterar SSID, senha, bandas, lista nativa de bloqueio ou VPN para simular sucesso do firewall.

## Fase 1 — Diagnóstico dentro do processo correto

Executar os probes no **Shizuku UserService que executa o controle de rede**, não apenas no processo da interface. Reutilizar a integração existente.

Registrar:

- Modelo do aparelho que fornece o hotspot, Android/API, versão do fabricante e versão do módulo de tethering, quando disponíveis.
- Versão/build do APK realmente instalado e identificação do build do UserService. Garantir que um serviço antigo não permaneça executando após atualização do APK.
- UID/PID do processo, `Shizuku.getUid()` no contexto apropriado, identidade shell/root e contexto SELinux quando legível.
- Capacidades efetivas do processo quando expostas, sem presumir que elas anulam outras restrições.
- Interfaces downstream/upstream, endereços e rotas relevantes, datapath ativo, estado da VPN e clientes associados.
- Separar erros de permissão, comando ausente, arquivo ausente, timeout, resposta vazia e falha de parsing.

Probes iniciais somente de leitura, executados separadamente e com saída limitada:

```text
id
id -Z
ip addr show
ip route show
ip -6 route show
ip rule show
ip -6 rule show
ip neigh show
ip -6 neigh show
iptables --version
iptables -S FORWARD
iptables -t nat -S
ip6tables -S FORWARD
```

Usar apenas os comandos presentes no aparelho. Disponibilidade de `nft`, `conntrack` ou APIs adicionais deve ser detectada, nunca presumida.

Implementar timeout real: consumir stdout/stderr sem bloquear indefinidamente antes de `waitFor`, limitar bytes e terminar processos que excedam o prazo. Registrar código de saída e erro original. Não executar probes de shell por pacote nas threads de encaminhamento.

### Descoberta de clientes

Preferir callbacks oficiais acessíveis ao serviço:

- `SoftApCallback.onConnectedClientsChanged`: associação e MAC.
- `TetheringEventCallback.onClientsChanged`: endereços reportados para os clientes.

Se callbacks estiverem indisponíveis, explicitar isso e usar observações de vizinhos limitadas à interface downstream como evidência complementar. Não confundir vizinhos upstream ou resultados de scan com clientes conectados. Validar a cobertura real de IPv6, inclusive endereços temporários.

## Fase 2 — Provar a opção A: filtragem com IP original visível

### A1. Identificar um ponto de filtragem utilizável

Inspecionar o encaminhamento real do aparelho e justificar onde a regra verá o endereço do cliente.

“Antes do NAT” descreve aqui a necessidade de preservar a identidade para decidir. Não significa colocar qualquer DROP em `nat/PREROUTING`. Em um caminho netfilter convencional, `filter/FORWARD` pode ver o IP original de origem no upload, antes de SNAT, e o destino já traduzido de volta ao cliente no retorno. Confirmar o caminho deste aparelho, a ordem das regras e possíveis atalhos/offloads.

Se uma API Binder for usada, documentar serviço, método, assinatura da versão, permissão exigida e resultado real. Reflection ou acesso ao Binder não remove a verificação de autorização.

### A2. Separar leitura, escrita e efeito real

Implementar três resultados independentes:

1. `canReadRules`: conseguiu listar.
2. `canWriteOwnedRules`: conseguiu criar, verificar e remover uma estrutura temporária própria, inicialmente sem ligação ao tráfego.
3. `selectiveEnforcementObserved`: bloqueou A de fato enquanto B permaneceu funcional.

Criar e remover uma chain vazia prova somente parte da capacidade de escrita. Não prova encaminhamento ou bloqueio.

Testar IPv4 e IPv6 separadamente. Não marcar suporte completo se somente uma família funcionar. Se for usada uma regra de roteamento em vez de netfilter, reportá-la como mecanismo distinto e comprovar seu efeito; `ip rule show` não é teste de instalação.

### A3. Teste temporário com dois clientes

- Gerar identificador exclusivo de teste; manter registro exato das regras/handles criados.
- Instalar somente regras específicas de A, limitadas ao encaminhamento entre downstream e upstream relevantes.
- Preservar associação Wi-Fi, DHCP e acesso local ao gateway; não bloquear INPUT/OUTPUT globalmente. Preservar também tráfego local entre clientes quando houver.
- Reconciliar todos os endereços verificados de A, inclusive IPv6. Se algum caminho não estiver coberto, reportar teste parcial.
- Observar deltas dos contadores das regras e testar tráfego real de A e B.
- Verificar conexões já abertas e novas: offload ou caminhos alternativos podem fazer uma regra funcionar apenas para parte do tráfego.
- Remover exatamente as regras próprias ao terminar, falhar ou cancelar. Disponibilizar recuperação de regras órfãs identificáveis após crash, sem tocar nas regras do Android ou de outros apps.

Não desativar offload como “correção” automática. Primeiro registrar o comportamento padrão. Uma eventual comparação com offload desativado deve ser um experimento separado, reversível e documentado; seu resultado não prova funcionamento na configuração padrão.

**Aprovar opção A somente após evidência de bloqueio seletivo real.** Se escrita for negada, registrar erro e avançar para B sem tentar contornar a proteção do sistema.

## Fase 3 — Provar a opção B: TUN + conntrack

Executar esta fase se A estiver indisponível ou para comparação diagnóstica.

### B1. Acesso real à tabela

Verificar, no processo Shizuku:

```text
/proc/net/nf_conntrack
/proc/self/net/nf_conntrack
/proc/net/ip_conntrack
/proc/self/net/ip_conntrack
```

Para cada caminho, registrar existência observada, abertura/leitura, erro, volume limitado lido e número de entradas relevantes parseadas. Ausência aparente também pode decorrer de restrições; preservar o erro original.

`cat` executado com a mesma identidade não ganha privilégios em relação à leitura do arquivo. Uma leitura vazia ou zero fluxos correlacionados não é necessariamente falta de permissão.

Se os arquivos não estiverem expostos, pode-se investigar uma interface conntrack via netlink ou ferramenta já presente, com suas permissões verificadas. Não presumir que outra interface evita as restrições de acesso.

### B2. Correlação com tráfego dos dois clientes

- Fazer A e B abrirem conexões simultâneas ao mesmo destino/porta.
- Correlacionar tuples originais e de resposta com o que o TUN observa.
- Considerar família IP, protocolo, endereços e portas; não usar apenas porta ou IP remoto como chave.
- Confirmar NAT com alteração de porta, upload/download e IPv6 com representação normalizada.
- Verificar ICMP, fragmentação e cabeçalhos de extensão IPv6: ausência de suporte não pode aparecer como bloqueio completo.
- Invalidar mapeamentos em desconexão, troca/reuso de endereço, encerramento/reuso de conexão e mudança de sessão/VPN.
- Não considerar `flowsParsed > 0` prova de cobertura de todos os clientes e fluxos.

### B3. Primeiro pacote e janela de liberação

O polling de conntrack pode chegar depois dos primeiros pacotes. Medir esse intervalo e testar UDP/QUIC, não somente conexões TCP longas.

Se pacotes de um cliente bloqueado escapam enquanto o cache está vazio, B **não passou**. Não esconder essa falha com testes que pré-carregam o cache. Qualquer estratégia de espera deve ter limites e comprovar que não prejudica B nem causa bloqueio global. Se não for possível resolver a identidade a tempo, reportar o limite arquitetural.

## Fase 4 — Validação física

Nos clientes de teste, desativar dados móveis e outros caminhos alternativos à internet. Usar requisições novas ou servidor de teste com resposta identificável para evitar confundir cache com conectividade. Registrar horários de cada ação e a família/protocolo efetivamente exercitados.

| Cenário | Resultado necessário |
| --- | --- |
| A e B permitidos | Ambos navegam; baseline registrado |
| Bloquear A | A permanece no Wi-Fi, perde internet; B continua navegando |
| Abrir conexões novas em A | Falham; não basta interromper uma conexão antiga |
| Transferência já aberta em A | Para conforme prazo medido e documentado |
| Desbloquear A | Internet volta sem reiniciar hotspot |
| Bloquear B com A permitido | Somente B perde internet |
| A sozinho bloqueado, depois B conecta | A permanece bloqueado; B funciona |
| B desconecta e reconecta | Regra de A não muda |
| A troca IP/reconecta | Política acompanha binding atual; endereço antigo não afeta B |
| IPv4, IPv6, TCP, UDP/QUIC e ICMP | Nenhum caminho de internet não coberto é tratado como sucesso |
| Mudança de VPN/upstream | Capacidade é reavaliada; ausência de proteção fica explícita |
| Cancelamento/erro do teste | Regras temporárias próprias são removidas e estado é reportado |

Repetir com upstream Wi-Fi e dados móveis quando disponíveis. Marcar `NOT_TESTED` quando não houver infraestrutura, IPv6 ou aparelhos suficientes. Falha de um teste de ping isolado não comprova bloqueio da internet.

Um terceiro cliente é desejável para regressão, mas a decisão inicial exige pelo menos dois clientes físicos.

## Logs e interface de diagnóstico

Adicionar uma entrada simples “Diagnóstico do firewall” com etapas, resultado e exportação de relatório. Separar probes de leitura do botão que inicia o teste temporário sobre o cliente escolhido. Isso é comportamento da ferramenta de diagnóstico; não solicitar acesso root como pré-requisito silencioso.

Estados sugeridos:

```text
NOT_TESTED
PERMISSION_DENIED
UNSUPPORTED
READ_ONLY
WRITE_CONFIRMED
PARTIAL_COVERAGE
SELECTIVE_BLOCK_OBSERVED
ENFORCEMENT_UNAVAILABLE
```

Exportar metadados limitados, sem payloads, senhas ou conteúdo de navegação:

```text
testId, timestamp, apkVersion, sourceCommit, serviceBuildId
device, androidApi, uid, selinuxContext, shizukuMode
downstreamInterface, upstreamInterface, datapathMode, vpnState
clientId, currentAddresses, mappingSource
probeName, exitCode, timedOut, boundedStderr
conntrackReadStatus, parsedFlows, attributedFlows, unmatchedDelta
ruleInstallStatus, ruleCounterDelta, cleanupStatus
clientAConnectivity, clientBConnectivity
```

Registrar evidências por intervalo e por versão da política, distinguindo DROP por bloqueio de descarte por controle de banda. Contadores antigos não justificam `Blocked (verified)`.

## Decisão final

| Resultado observado | Decisão |
| --- | --- |
| A escreve e bloqueia seletivamente, cobrindo os caminhos testados | Preferir A; documentar matriz de suporte e testes pendentes |
| A indisponível; B atribui corretamente e bloqueia sem janela de vazamento | Considerar B para a configuração validada |
| B apenas lê alguns fluxos ou funciona com cache sintético | Insuficiente; não declarar suporte |
| A e B indisponíveis/incompletos | Reportar que bloqueio de internet mantendo Wi-Fi não foi viabilizado nessa configuração |

O bloqueio nativo `setBlockedClientList` é uma alternativa de produto que desconecta o cliente. Está fora do critério de sucesso desta tarefa e não deve ser usado para fazer o teste parecer aprovado.

## Entregáveis para a IA desenvolvedora

1. Código do diagnóstico e teste temporário, com mudanças pequenas e identificadas.
2. APK de teste identificado por versão/build e SHA de origem, se houver ambiente de build.
3. Relatório dos probes e matriz preenchida com resultados reais ou `NOT_TESTED`.
4. Conclusão fundamentada: A, B ou indisponível; separar fatos de hipóteses.
5. Comprovação da remoção das regras temporárias, incluindo falhas de cleanup.
6. Testes automatizados úteis: classificação de erros, cleanup, bindings obsoletos, reuso de fluxo, cache vazio e estado da UI. Identificar fixtures sintéticas como tais.

Se não houver acesso físico ao telefone, entregar a instrumentação e o roteiro para o usuário executar. **Não inventar resultados nem apresentar compilação como validação de rede.**

## Fontes e referências

- [Android: tethering, NAT, DHCP, IPv6 e offload](https://source.android.com/docs/core/ota/modular-system/tethering).
- [Android: APIs Soft AP, callbacks, listas e capacidades](https://source.android.com/docs/core/connect/wifi-softap).
- [Shizuku: diferenças entre ADB/root, Binder e UserService](https://github.com/RikkaApps/Shizuku-API).
- [Permissões do shell no AOSP Android 14](https://github.com/aosp-mirror/platform_frameworks_base/blob/android14-release/packages/Shell/AndroidManifest.xml). Referência de plataforma, não prova das capacidades do aparelho do usuário.
- [TunTrafficEngine da revisão analisada](https://github.com/geraldotech/shizzyluna/blob/0b0d7595ffc5605b3582bd639c3f7ff14cbd10e2/app/src/main/java/dev/shizzi/TunTrafficEngine.kt).
- [HostFirewall da revisão analisada](https://github.com/geraldotech/shizzyluna/blob/0b0d7595ffc5605b3582bd639c3f7ff14cbd10e2/app/src/main/java/dev/shizzi/HostFirewall.kt).
