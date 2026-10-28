# Shizzy Lua.7 — Especificação de correção do parser BPF

**Repositório:** https://github.com/geraldotech/shizzyluna  
**Base de análise:** branch `main`, consultada em 27/10/2026  
**Objetivo:** instrumentar e corrigir a coleta/parsing de `dumpsys tethering bpf`, sem atribuir fluxos ao cliente errado.  
**Destinatário:** LLM/engenheiro responsável pela implementação Kotlin/Android.

> **Importante:** o relatório anterior cita nove linhas rejeitadas e 98 mapeamentos válidos, mas as nove linhas brutas não foram fornecidas nesta tarefa. Esses números são contexto do diagnóstico, não uma reprodução verificada. **Não invente os nove exemplos nem assuma sua causa.** Primeiro produza diagnósticos que permitam capturá-los.

## 1. Código real a modificar

Os componentes estão no mesmo arquivo, e **não** em `BpfDumpParser.kt` separado:

| Componente | Caminho | Referência aproximada na `main` |
| --- | --- | --- |
| `BpfDumpParser` | `app/src/main/java/dev/shizzi/BpfFlowAttribution.kt` | linhas 131–492 |
| `NatFlowAttributor` | mesmo arquivo | a partir da 612 |
| `BpfMapReader` | mesmo arquivo | a partir da 1134 |
| Relatório BPF | mesmo arquivo, `BpfAttributionStatusReport.toMarkdownReport` | a partir da 1533 |
| Testes | `app/src/test/java/dev/shizzi/BpfFlowAttributionTest.kt` | testes atuais |

Inspecione a versão efetiva desses arquivos antes de editar: as referências de linha podem mudar. Preserve a arquitetura existente e as alterações de outros desenvolvedores.

## 2. Diagnóstico confirmado pelo código

1. `BpfDumpParser.parse` armazena `BpfRejectedLine(lineNumber, section, reason, linePreview)` quando rejeita uma linha IPv4. O `linePreview` está limitado a 120 caracteres.
2. A regex `IPV4_FLOW_ROW_REGEX` espera, entre outras coisas, `N(label)`, três pares IPv4:porta, dois MACs entre colchetes, PMTU numérico e idade terminada em `ms`. Variações reais de formato podem resultar em `INVALID_SYNTAX`, mas **não sabemos se foi essa a causa das nove rejeições**.
3. `NatFlowAttributor.ingestParsedDump` (aprox. linhas 745–762) retorna `false` sempre que `!parsed.recognizedFormat || parsed.hasRejections`, mesmo que haja entradas aceitas. Isso explica o descarte do novo snapshot como um todo. Um snapshot válido anterior pode continuar sendo utilizado enquanto estiver fresco.
4. `BpfMapReader.collectOnce` reduz o erro a uma mensagem que inclui apenas o total de rejeições e o motivo da primeira (aprox. linhas 1262–1275).
5. `toMarkdownReport` exporta `Rejected Parse Lines`, mas não exporta número, seção, motivo e amostra das rejeições.
6. O parser classifica `pmtu <= 0` ou `ageMs < 0` como `INVALID_IFINDEX` junto dos índices inválidos; isso mistura causas distintas.
7. O filtro de interfaces aceita rótulos somente numéricos sem validar o `ifindex` contra a interface ativa. **Não atribuir esse comportamento às nove rejeições sem evidência.**

## 3. Etapa A — instrumentação obrigatória (primeiro PR)

### A1. Representar e conservar rejeições

- Preservar `lineNumber`, `section`, `reason` e `linePreview` do parser até a camada de diagnóstico, inclusive quando `ingestParsedDump` rejeitar o snapshot.
- Manter o resultado de diagnóstico da **última tentativa** separado do **último snapshot publicado**. Não fazer uma tentativa com erro sobrescrever fluxos previamente validados nem apresentar os dois como se fossem a mesma coleta.
- Acrescentar contagem de entradas IPv4 upstream/downstream aceitas, rejeições por motivo, `recognizedFormat`, status da execução (`OK`, `TIMEOUT`, `TRUNCATED`, etc.) e indicação explícita de `snapshotPublished`.
- Exportar no relatório Markdown as rejeições de forma limitada e previsível (por exemplo, até 20), com número, seção e motivo. Informar quantas foram omitidas pelo limite.
- Para reprodução detalhada, oferecer um modo explícito de exportar trechos suficientes para identificar o formato da linha. **Não colocar IPs públicos/privados, portas ou MACs integrais em telemetria padrão**; usar redação/mascaramento por padrão e permitir exportação sensível apenas por escolha consciente do usuário, reaproveitando o padrão `includeSensitiveEndpoints` quando adequado.
- Não despejar indiscriminadamente `stdout` completo em logs persistentes. Respeitar os limites de bytes e timeout já existentes.

### A2. Classificação de erros

- Separar sintaxe incompleta de truncamento comprovado. O simples fato de uma linha com `->` não terminar em `ms` **não prova** truncamento pelo leitor.
- `wasTruncatedByReader` continua sendo o sinal autoritativo de corte por limite de bytes.
- Corrigir o diagnóstico de índices, PMTU e idade: motivos específicos, sem chamar PMTU/idade inválidos de `INVALID_IFINDEX`.
- Tratar como rejeição apenas linhas que comprovadamente pretendem representar entradas da seção de fluxo. Não confundir mensagens, cabeçalhos, totais ou marcadores vazios legítimos com fluxos defeituosos.
- Não enfraquecer validação de IP, porta, MAC, protocolo e `ifindex` para fazer um teste passar.

### A3. Reproduzir o caso real

1. Gerar APK instrumentado e coletar novo relatório no mesmo tipo de sessão onde ocorreu a falha.
2. Capturar as linhas rejeitadas ou um trecho fiel de `dumpsys tethering bpf` (com dados sensíveis sob controle).
3. Criar fixture anonimizada que **preserve a estrutura sintática exata** e teste de regressão para cada variante válida.
4. Classificar cada linha real: fluxo válido em formato ainda não suportado, metadado não-fluxo, conteúdo inválido ou saída efetivamente truncada.
5. Sem essa evidência, encerrar o primeiro PR como **instrumentação**, não como correção definitiva do formato.

## 4. Etapa B — parser e política de publicação (após evidência)

### B1. Ajustes do parser

- Aceitar somente variantes de sintaxe demonstradas pelo `dumpsys` real ou documentação/plataforma correspondente.
- Criar fixtures para IPv4 upstream/downstream, `tcp`/`udp`, índice `N(label)`, rótulo numérico e interfaces nomeadas, MAC em maiúsculas/minúsculas, linhas vazias, `none`, cabeçalhos e truncamento.
- Garantir que campos de origem, tradução e remoto mantenham a direção correta. O MAC no início da linha upstream **não é** o MAC do cliente.
- Proibir criação de `NatFlowMapping` com índices, endereços ou portas inválidos.

### B2. Não liberar snapshots parciais sem prova de segurança

**Não substituir simplesmente** `if (parsed.hasRejections) return false` por aceitação irrestrita. O conjunto parcial pode omitir um fluxo contraditório e atribuir incorretamente um tuple NAT a um cliente.

Implementar decisão explícita de coleta:

- **Fatal:** truncamento do leitor, falha do comando, cabeçalho obrigatório não reconhecido ou integridade comprometida. Não publicar novo snapshot.
- **Ignorável com prova:** metadado/cabeçalho conhecido que não representa fluxo. Não contar como fluxo rejeitado.
- **Fluxo malformado/ambíguo:** por padrão não publicar uma visão parcial como completa. Se houver suporte a snapshot parcial, provar que ele contém apenas tuplas seguras, marcar `coverageIncomplete`, impedir política permissiva baseada em ausência de fluxo e manter a semântica conservadora para tuplas desconhecidas. Exigir testes que demonstrem não atribuição cruzada.

Preservar a proteção contra: duplicidade de tupla traduzida, conflitos IP↔MAC, inconsistência na direção reversa, troca de sessão/upstream, reutilização de TCP SYN, expiração e limites de cobertura.

### B3. `ifindex`

- Investigar a fonte da interface downstream e upstream e comparar com `inIfIndex/outIfIndex` observados.
- Não usar apenas o rótulo numérico `215(215)` como prova de que a interface é a ativa.
- Verificar paridade da direção reversa (`down.inIfIndex == up.outIfIndex`, `down.outIfIndex == up.inIfIndex`) já aplicada em `exactDown`.
- Caso a associação nome→índice não esteja disponível com confiança, registrar a limitação e evitar atribuição presumida; não inventar números de interface.

## 5. Testes obrigatórios

Ampliar `BpfFlowAttributionTest.kt` e, se útil, criar testes unitários focados no parser e no leitor com `commandRunner` injetado.

| Caso | Resultado esperado |
| --- | --- |
| Dump conhecido com fluxos válidos | Todos os campos e contagens corretos; snapshot publicado |
| Linha realmente truncada por limite | Status `TRUNCATED`; nenhum snapshot incompleto publicado |
| Uma linha IPv4 inválida em meio a válidas | Rejeição com seção/número/motivo; política de publicação segura e documentada |
| Formato válido novo capturado no aparelho | Fixture passa sem mascarar outro erro |
| Texto `none`, cabeçalhos e metadados | Sem falsos positivos de rejeição |
| MAC do hotspot no campo upstream | Nunca tratado como MAC do cliente |
| IP↔MAC discordante da direção reversa | Tupla não atribuída ao cliente errado |
| Tuplas traduzidas duplicadas/conflitantes | Resultado ambíguo, não escolher o primeiro |
| Índices upstream/downstream trocados ou não compatíveis | Não fazer vínculo indevido |
| Falha após snapshot válido | Preservar snapshot anterior apenas conforme geração e frescor |
| Relatório com rejeições e mascaramento | Diagnóstico útil sem vazar endpoints por padrão |
| Dois clientes com políticas diferentes | Bloquear/limitar um não afeta o outro |

Executar a suíte de testes localmente com o Gradle apropriado ao projeto. Se a execução depender de SDK, ambiente ou dispositivo não disponível, registrar o comando tentado, o impedimento e quais testes não foram executados; **não alegar testes aprovados sem execução**.

## 6. Critérios de aceitação

- [ ] Relatório permite identificar com precisão todas as nove rejeições em nova reprodução (ou registra explicitamente que o cenário não pôde ser reproduzido).
- [ ] Causa de cada rejeição classificada com base no dump real, e não em hipótese.
- [ ] Teste de regressão para cada formato válido anteriormente rejeitado.
- [ ] Erros fatais não publicam snapshot incompleto.
- [ ] Nenhum pacote é atribuído ao MAC de cliente diferente devido a dados BPF parciais, contraditórios ou antigos.
- [ ] Status da coleta e último snapshot publicado são distinguíveis na UI/relatório.
- [ ] `ifindex` investigado com evidências, sem conversão silenciosa entre nome e índice.
- [ ] Testes executados e resultados descritos no PR.
- [ ] Nenhuma alteração desnecessária em UI, arquitetura de políticas ou randomização de MAC.

## 7. Entrega esperada da LLM implementadora

1. Criar branch de correção a partir de `main`; não fazer push direto em `main`.
2. Entregar primeiro a Etapa A em commit/PR isolado, com testes unitários.
3. Apresentar diff resumido e relatório de testes; fornecer instruções exatas para capturar a saída real no aparelho.
4. Após receber o dump, entregar Etapa B em novo commit/PR, com fixtures fiéis e justificativa da política de snapshots parciais.
5. Informar riscos residuais: cobertura BPF não síncrona, primeiros pacotes ainda não mapeados, mudanças de interfaces e MAC aleatório.

**Proibição expressa:** não resolver a falha removendo todas as validações, usando MAC do hotspot como cliente, aceitando qualquer tupla por aproximação, desabilitando proteção contra ambiguidade ou expondo tráfego/identificadores sensíveis por padrão.
