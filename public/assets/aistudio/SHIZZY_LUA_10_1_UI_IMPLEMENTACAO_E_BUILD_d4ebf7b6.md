# Shizzy lua.10.1 — Ajustes de UI sem regressão do firewall

## Missão para a LLM implementadora

Implementar **somente** as alterações de interface detalhadas neste documento, executar os testes e gerar um APK instalável. Trabalhar sobre o repositório `https://github.com/geraldotech/shizzyluna`, partindo do commit **`ab2e16dcef1590fe09358fc462cf3a3561439602`** (`v10`, versão `0.4.0-rs-lua.10`, `versionCode=15`). Se a branch tiver avançado, registrar o HEAD real e comparar as mudanças antes de editar. Preservar integralmente os fluxos BPF/NAT, atribuição MAC, motor VPN rootless, bloqueio, shaping e persistência das regras existentes.

**Critério principal:** interface mais simples, mesmos resultados funcionais do lua.10. Não reescrever o firewall, não introduzir `iptables`, não alterar semântica de NAT, não publicar snapshots BPF parciais para contornar erros, nem modificar o comportamento de pacotes desconhecidos nesta versão.

## Estado funcional a preservar (evidência real, Galaxy)

- Com BPF habilitado: `collectionStatus=OK`, `lastAttemptSnapshotPublished=true`, `lastAttemptRejectedLineCount=0`, 252 fluxos com correspondência reversa e 3 clientes identificados.
- Observados: `bpfAttributedPackets=353287`, `blockedDropPackets=762`, `shapedPackets=69727`, `shapingDropPackets=2076`.
- Usuário confirmou bloqueio e limitação de velocidade em três dispositivos; ao desativar BPF, o bloqueio deixou de atuar. Portanto, manter BPF ligado por padrão e **não mexer nos mecanismos de enforcement**.
- Existe limitação conhecida: tráfego sem atribuição recebe ALLOW; não resolver isso no pacote 10.1 de UI.

## Localização das alterações

1. **`app/src/main/java/dev/shizzi/ui/ClientsPage.kt`** — principal e preferencialmente único arquivo de UI modificado.
   - Cartão `experimental_bpf_card` próximo das linhas 224–317.
   - Composable `ConfigureClientDialog` próximo das linhas 789–1006.
   - Badges das regras nos cartões próximos das linhas 677–715.
2. **`app/src/main/java/dev/shizzi/ui/SettingsPage.kt`** — **preservar**, não remover o toggle BPF na seção Developer nem a opção `Diagnóstico do firewall & BPF NAT`.
3. **`app/build.gradle.kts`** — atualizar versão conforme seção Build.
4. Testes Compose/UI e testes unitários existentes; adicionar testes cirúrgicos para conversões e validação do formulário.

Use os caminhos reais do HEAD e evite alterações desnecessárias em outros arquivos. Caso uma modificação fora desse escopo seja indispensável, explique-a no relatório final.

## Mudança 1 — remover controles BPF duplicados em Connected Devices

Na tela **Connected Devices**, remover completamente o cartão destacado em rosa:

- Título `Experimental BPF NAT Attribution` e seu switch.
- Texto `State / Poll`, telemetria, `Collection`, `Mapped flows`, pacotes e aviso interno do cartão.
- Botão `BPF & Firewall Diagnostics`.
- Botão `Collect BPF` que integra o mesmo cartão.

Isto é **remoção apenas da apresentação na tela de clientes**. Não eliminar os callbacks do modelo/API se utilizados em outros lugares, nem desabilitar polling/BPF ou apagar telemetria. A configuração BPF e o acesso ao diagnóstico continuarão disponíveis na **Settings → Developer** (tela vermelha do print). Preservar o restante de Connected Devices: busca, lista, badges, botões e alerta de fallback.

O bloco `Card` com tag `experimental_bpf_card` pode ser removido da composição e imports/variáveis agora não utilizados devem ser limpos. Ajustar chamadas/assinaturas apenas se necessário e sem quebrar outras telas. Não é obrigatório criar indicador novo nesta versão; priorizar simplicidade.

### Aceite

- Nenhum controle BPF/diagnóstico duplicado aparece em Connected Devices.
- Toggle `Experimental BPF NAT Attribution` e opção `Diagnóstico do firewall & BPF NAT` permanecem visíveis e operacionais em Settings.
- Ao abrir Connected Devices, BPF continua rodando com a preferência salva; nenhum efeito colateral ao remover o `Card`.

## Mudança 2 — Bandwidth Limit com input numérico em Mbps

Em `ConfigureClientDialog`, substituir **somente** o `FlowRow` com chips `Unlimited`, `512 Kbps`, `1 Mbps`, `2 Mbps`, `5 Mbps`, `10 Mbps`, `25 Mbps` por um único `OutlinedTextField` de valor numérico decimal:

- Rótulo: **`Bandwidth Limit (Mbps)`**.
- Ajuda: **`0 = Unlimited. Applied separately to download and upload.`**
- Teclado numérico decimal (`KeyboardType.Decimal`), uma linha, sufixo visual `Mbps` quando apropriado.
- Aceitar `0`, inteiros e decimais com ponto; opcionalmente aceitar vírgula decimal do teclado/locale, normalizando no parser.
- **Valor persistido permanece `ClientRule.bandwidthLimitKbps: Int`.** Não renomear o campo, não mudar storage JSON, não converter motor para MB/s. Fórmula: `kbps = Mbps × 1000`.
- `0` → `0 Kbps` (ilimitado). `0.5` → `500 Kbps`; `1` → `1000 Kbps`; `1.5` → `1500 Kbps`; `10` → `10000 Kbps`.
- Ao abrir regra já salva, fazer conversão reversa `bandwidthLimitKbps / 1000` sem perder precisão: `512 Kbps` deve aparecer como `0.512` Mbps e salvar novamente como **512 Kbps**, não 500 nem 1000. Evitar float binário que arredonde incorretamente; preferir `BigDecimal`, parser decimal estrito e conversão exata/definida.
- Rejeitar entrada vazia, negativa, NaN, texto alfabético, frações com precisão superior à suportada em Kbps e overflow de `Int` **com mensagem inline e Save Rules desabilitado**. Não transformar automaticamente entrada temporariamente vazia em `0` ao digitar.
- Escolher um limite superior coerente com `Int.MAX_VALUE` em Kbps e validar explicitamente; sem truncamento silencioso.
- Armazenar o texto como estado de edição e converter na hora de salvar; não mudar políticas enquanto o usuário digita (aplicar somente em Save Rules).

Preservar **Connection Time Limit** e seus chips atuais (`Unlimited`, `15m`, `30m`, `1h`, `2h`, `4h`) — o pedido é remover somente os presets da **velocidade**, não os presets de duração.

### Aceite

- Nova regra: valor inicial `0` com ilimitado.
- Editar uma regra prévia `512 Kbps` mostra `0.512`, salvar sem alteração mantém exatamente `512 Kbps`.
- `0`, `0.5`, `1`, `1.5`, `25` geram 0, 500, 1000, 1500, 25000 Kbps.
- Campos inválidos impedem Save Rules, com feedback compreensível.
- Configuração de limite continua sendo por MAC e por direção; não aplicar limite global em `192.0.2.2`/`2001:db8::2`.
- Badge de limite existente nos cartões continua coerente com o valor salvo; se exibir `0.512 Mbps`, não arredondar para `1 Mbps`.

## Mudança 3 — Scheduled Access Window por seleção de horas inteiras

Substituir os dois `OutlinedTextField` com `Start Hour (0-23)` / `End Hour (0-23)` por controles intuitivos de seleção **apenas de horas**, mantendo os campos persistidos atuais:

- `scheduleEnabled: Boolean` intacto.
- `scheduleStartHour: Int` e `scheduleEndHour: Int`, intervalo `0..23`, intactos.
- UI recomendada: dois botões/campos clicáveis `Start time` / `End time` que abrem um seletor de hora. **Não permitir minutos diferentes de `00`**; se o TimePicker Android não permitir restringir minutos de maneira confiável, usar um diálogo Compose de seleção das 24 horas (grade/lista com acessibilidade), evitando qualquer minuto editável.
- Mostrar no formulário, por exemplo, `08:00 → 22:00` e texto explicativo: **`Internet allowed from 08:00 to 22:00. Outside this window, access is blocked.`**
- Respeitar janela que cruza meia-noite: `22:00 → 06:00`. A lógica existente de `HostFirewall.enforce` já suporta `start > end`; não alterá-la.
- **Proibir `start == end` quando o agendamento está ativo**, com erro inline; na lógica atual o intervalo com horas iguais não concede nenhuma hora. Não interpretar automaticamente como 24 horas ou alterar regra salva sem confirmação. Se existir regra antiga com horas iguais, mostrar alerta e exigir seleção válida antes de novo Save.
- Quando o switch está desligado, esconder/desabilitar os seletores, mas preservar as horas existentes ao reativar; valor armazenado continua inalterado quando só desliga a programação.
- Exibir horário formatado como `HH:00` (zero à esquerda). Adotar `24h` independente da preferência de relógio do sistema, já que os dados são horas `0..23`.
- `Save Rules` deve continuar salvando alias, bloqueio, banda, duração e agendamento juntos, sem sobrescrever campos não editados.

### Aceite

- Janela `08:00–22:00` salva `8,22` e permite apenas essas horas (sem mudar `HostFirewall`).
- Janela `22:00–06:00` salva `22,6` e mantém tratamento de overnight.
- `08:00–08:00` é inválido com agendamento ligado.
- Agendamento desligado preserva as horas configuradas.
- Nenhuma mudança no formato de armazenamento nem migração de regras.

## Limites estritos de escopo

**Não alterar:** `BpfDumpParser`, `BpfMapReader`, `NatFlowAttributor`, `TunTrafficEngine`, `HostFirewall` (exceto se algum teste demonstrar uma incompatibilidade objetiva introduzida por esta UI, caso em que reportar antes), `TetherSession`, processamento de pacotes, bridge TUN, resolução `ifindex`, contador, AQM, token bucket, MAC/IP e defaults de BPF.

**Não introduzir:** `iptables`, root, novos privilégios, serviço VPN alternativo, mudança de estratégia de bloqueio de pacotes desconhecidos, nova opção de modo de identificação ou alteração da semântica de schedule no engine.

**Sem alterações silenciosas:** manter nomes e persistência dos campos `ClientRule`. Não remover configurações de outros pontos da aplicação. Preferir componentes Compose já existentes do tema Shizzy; respeitar modo escuro, rolagem do diálogo, teclado, acessibilidade e layouts estreitos.

## Plano de implementação recomendado

1. Registrar commit HEAD e confirmar que `lua.10` está disponível; criar branch de trabalho `ui/lua-10-1` se houver permissão.
2. Ler `ClientsPage.kt`, `SettingsPage.kt`, `ClientRule`, `SettingsStore.kt` e os testes relevantes.
3. Extrair, se útil, funções puras testáveis para `formatKbpsAsMbps`, `parseMbpsToKbps` e `isValidScheduleHours`, sem alterar modelo persistente.
4. Remover cartão duplicado e adicionar input de banda/seletores de hora; preservar limites de duração.
5. Adicionar Compose testTags estáveis aos novos campos/seletores e testes de integração do formulário.
6. Rodar unit tests, build e testes instrumentados se um Android/emulador estiver disponível. Não declarar testes de hardware como executados se não houve Galaxy conectado.
7. Revisar diff para garantir que somente arquivos de UI, testes e versão foram alterados. Compilar APK e emitir SHA256.

## Testes obrigatórios (automatizados)

1. `parseMbpsToKbps("0") == 0`.
2. `0.5 → 500`, `1 → 1000`, `1.5 → 1500`, `25 → 25000`, `0.512 → 512`.
3. Roundtrip **para todos os presets legados**, em especial `512 Kbps` e `25000 Kbps`.
4. Rejeição de negativo, vazio, valor excessivamente grande, alfabético e casas decimais impossíveis de representar como Kbps inteiro.
5. Mudança no campo sem salvar não altera a regra persistida.
6. Salvar preserva `mac`, `alias`, `isBlocked`, `connectionTimeLimitMinutes`, `scheduleEnabled`, `scheduleStartHour` e `scheduleEndHour` não modificados.
7. Horas `0..23` são selecionáveis; nunca há minuto diferente de `00`.
8. Agendamento diurno `8–22`, overnight `22–6`, e erro para `8–8` quando habilitado.
9. Switch desligado não apaga horários salvos.
10. Tela Connected Devices não contém o cartão duplicado, mas Settings ainda contém toggle BPF e diagnóstico.
11. Executar todos os testes de regressão existentes do BPF (incluindo linhas `ifindex`, idades `-`, delta negativo, publicação de snapshot, MAC/NAT, bloqueio/banda).
12. Build deve completar sem erros de compilação ou warnings novos de uso inseguro de API/Compose.

Executar ao menos:

```bash
gradle :app:testDebugUnitTest :app:assembleDebug
```

Se houver wrapper Gradle no repositório, preferir `./gradlew :app:testDebugUnitTest :app:assembleDebug`. Se testes de UI dependem de dispositivo, executar com Android disponível ou marcar explicitamente como **PENDENTE**, sem simular aprovação.

## Controle de versão e APK

- Atualizar `app/build.gradle.kts` para `versionName = "0.4.0-rs-lua.10.1"` e `versionCode = 16` (desde que `16` ainda esteja livre no HEAD).
- Atualizar `SERVICE_BUILD_ID = 16` e `SOURCE_COMMIT` conforme convenção do projeto, registrando o commit real da base e sufixo `+lua.10.1` sem fingir que o APK contém um commit ainda não criado.
- Gerar `shizzy-lua10.1.apk` e preservar `app/build/outputs/apk/debug/app-debug.apk`.
- Publicar a branch/commit se o ambiente estiver autorizado. Não substituir/destruir o APK funcional `shizzy-lua10.apk`.
- Calcular SHA256 do APK e registrar comando, resultado, tamanho, versionName, versionCode, serviceBuildId, base commit, commit das alterações, e caminho verificável para baixar.

## Checklist de validação física no Galaxy (usuário executará)

- Confirmar versionName **0.4.0-rs-lua.10.1** / build **16** no app/diagnóstico.
- Abrir Connected Devices: painel rosa sumiu; Settings Developer continua com BPF + diagnóstico.
- Cliente com regra antiga `512 Kbps`: abrir, observar `0.512`, salvar, reabrir (mesma velocidade).
- Cliente A bloquear/desbloquear; B limitar a `1.5 Mbps`; C ficar livre. Confirmar A bloqueado, B próximo do limite, C navegando. Conferir que os outros não são afetados.
- Agendar `08:00–22:00` e `22:00–06:00`; conferir visual e persistência sem precisar aguardar a virada da hora para validar UI.
- Conferir BPF `collectionStatus=OK`, snapshot publicado e contadores `bpfAttributedPackets`, `blockedDropPackets`, `shapedPackets`; não exigir números absolutos iguais ao teste lua.10.
- Exportar JSON se houver regressão; reverter ao APK lua.10 antes de qualquer experimento de backend.

## Entrega obrigatória da LLM implementadora

Responder com:

1. **Commit de base e commit final**, lista e resumo de arquivos modificados.
2. Prints da nova tela Connected Devices e do Configure Host Rules, se ambiente permitir.
3. Tabela dos testes executados (PASS/FAIL/PENDENTE), incluindo contagem; não confundir unit tests com teste físico.
4. APK `shizzy-lua10.1.apk`, versão/código de build e SHA256.
5. Declaração explícita de que **não alterou parser BPF, atribuição NAT/MAC, VPN, firewall, shaping ou persistência**.
6. Lista de riscos conhecidos e itens pendentes de teste no aparelho.

## Condição de parada

Se os testes de regressão existentes falharem, se o build não terminar, se o projeto tiver divergência de versão relevante ou se uma mudança exigir mexer no núcleo de tráfego, **não declarar conclusão e não liberar APK como validado**. Relatar o problema e pedir orientação. A prioridade é preservar o lua.10 funcional.
