# V3 cumulativa — implementação Bitcoin e evidências para teste

Base oficial: `mainnetswap`, commit `7d9d41a1fd4a67ed25bf437846c739ee18f5cb36`.
Branch local: `interop/security-hardening-20260908`. A V3 acumula V1 e V2.
SHA-256 do ZIP V2 preservado: `81410810a8c0b59657582cd1028807924489480153867c2322575466ec8c07ee`.

**Há código novo aplicado; esta entrega não conclui a meta 10/10.** O transporte
pelo root, a prontidão bilateral DOM e a retomada completa do daemon ainda não
estão conectados. Nenhuma das quatro rotas completas foi executada aqui.
Não há compilação Rust confirmada nem auditoria independente desta versão.

## Executar no seu ambiente

Extraia o ZIP em uma pasta nova, entre em `dom-protocol` e execute:

```bash
python3 scripts/test_interop_hardening.py --format --mode full
```

Requer Linux, Python 3, Git, Rust/Cargo/rustfmt (1.96.1 usado no workflow),
compilador C, clang, cmake, pkg-config, Bitcoin Core (`bitcoind`, `bitcoin-cli`),
Foundry (`forge`, `anvil`), curl e acesso às dependências ou cache existente.
O script não instala dependências nem usa credenciais de produção.

Para componentes sem os nós, use `--format --mode components`. Para as
verificações Python sem Rust ou nós:

```bash
python3 scripts/test_interop_hardening.py --mode offline
```

Saída 0: comandos selecionados concluídos; 1: falha; 2: ferramenta ausente.
Relatórios e logs ficam em `artifacts/interop-hardening/`, com hashes do código
antes/depois e de cada log. `full` inclui testes de componentes e scripts
existentes Bitcoin/Anvil; **não é uma campanha das quatro rotas pelo daemon**.

Nos modos `components` e `full`, o teste Rust novo exporta
`rust-participant-round-v3.json`. O comando seguinte verifica essas mensagens
por uma implementação Python, sem importar o signer Rust. Se o teste não
produzir o arquivo, a verificação falha; não usa um exemplo pré-fabricado como
substituto. Essa comparação cruzada ainda não foi executada aqui.

## O que foi implementado

### Mensagens autenticadas entre participantes

`crates/btc-actuator/src/participant_wire.rs` implementa frames V3 limitados a
270 bytes: nonce público ou parcial, papel, identidade do participante, digest
completo da sessão, política M.8 e evidência das âncoras, autenticados por BIP340.
A chave vem da autoridade local já vinculada ao roster; não há API pública de
assinatura arbitrária. Cada destinatário confere a própria autorização M.8,
o participante oposto e a assinatura antes de gravar material remoto no banco.

A parcial inclui o digest do transcript. O actuator exige correspondência ao
transcript persistido antes da agregação, que ainda verifica a parcial MuSig2
pelo backend real. Frames truncados, extensões, papéis trocados, reflexão e
alterações de assinatura/contexto são recusados. Decodificar um frame não o
autentica: somente consumi-lo pelos métodos do actuator faz essa verificação.

O nonce/parcial criptográfico continua no vault/journal existente. A assinatura
de autenticação BIP340 usa aux zero, reproduzindo o mesmo frame no replay;
a aleatoriedade de blindagem do contexto não altera os bytes da assinatura.
Não se gera outro nonce MuSig2 para repetir uma mensagem.

**Compatibilidade:** este é um protocolo candidato novo `DOMBTCM3`, não um
payload DSC1 existente. Ele não deve ser reetiquetado ou entregue por um relay
que não possua uma transição explicitamente compatível. O transporte de rede
não está implementado por esse codec. Requer revisão criptográfica da nova
superfície de assinatura antes de ativação operacional.

### Capacidade F7 → signer local → claim

Em `production_chain_signers.rs`, a nova invocação consome a capacidade local
emitida por F7/M.8 para o mesmo participante, papel e perna. Usa a chave e o
vault já retidos pelo Stage 8, sem abrir outra autoridade ou reunir duas chaves.
Há métodos concretos para expor nonce, produzir parcial e agregar. A agregação
emite uma autoridade opaca que se vincula ao materializador, aos termos, ao
plano de papéis e aos scopes de origem do segredo.

Cada invocação exige uma nova capacidade local validada; o wrapper não aceita
uma janela temporal bruta fornecida pelo transporte. O resultado público do
peer que já existia em F7 continua apenas uma comparação local.

### Funding exato e extração no child Bitcoin

O caminho de claim por participantes deixava passar `ActuatorReady` sem conferir
qual funding a autoridade possuía. Agora compara rede, route/termos/deployment,
txid, vout, principal, script autenticado pelo registro Prepared e CSV com sua
unidade. O script da sessão é reconstruído no signer a partir do roster, chave
de refund e CSV; essa comparação o liga ao funding efetivamente retido.

`finalize_claim_with_extraction` conserva um contexto público de extração,
verificado contra os bytes exatos e a assinatura final. O child só entrega esse
contexto após conferir a operação terminal durável. O handoff reutiliza o Core
client existente; seu coletor prova a transação canônica e as confirmações
antes de extrair o segredo. A fonte pública Bitcoin aceita esse handoff e a
recuperação Fresh anterior. Não há um segundo broadcaster ou cópia de wallet.

### Recuperação sem restaurar o segredo adaptor

`reconcile_takeover` agora atualiza a época da operação Claim e de seu transcript
na mesma transação SQLite. Antes, uma operação finalizada podia ser re-fenciada
sem seu transcript, causando recusa pela auditoria relacional na retomada.

`recover_claim_extraction_v3` exige lease/scope atuais, identidade local,
autorização M.8 e parcial remota já verificada. Reconstrói a pré-assinatura do
transcript/vault retidos e a vincula ao claim canônico armazenado. Não recebe o
escalar adaptor e não transmite transação. O vault e a chave local continuam
necessários; isso não é recuperação após perda total dos arquivos/chaves.

A regressão Rust nova usa bancos físicos separados, fecha e reabre actuator e
vault, troca o proprietário, confere replay idêntico, finaliza o claim, reabre
novamente e recupera o mesmo contexto. O RPC é um test double que conta
transmissões; o teste exige zero transmissões na reconciliação/extração. Não
simula todos os crashes possíveis nem substitui um Bitcoin Core real.

### Verificador independente das mensagens

`scripts/bitcoin_participant_oracle.py` confere framing, os quatro envelopes
BIP340, os pins da sessão/M.8/participantes e o digest dos dois nonces no
transcript. Compartilha apenas primitivas Python com o verificador independente
de claims da V2. Não reutiliza a lógica de decisão Rust.

Há cinco testes adicionais com chaves sintéticas conhecidas: sucesso,
substituições em tags/contexto/payload/assinatura, truncamento/extensão/reflexão,
roster/schema/pins inválidos e códigos de saída do CLI. Os pins precisam de
uma origem autenticada externa. Não verifica prova F7, parciais MuSig2, inclusão
em cadeia nem liveness. A fixture assinada em Python é somente teste; o runner
separadamente exige a fixture realmente produzida pelo teste Rust.

## Limite da integração nesta entrega

O root ainda não dirige a prontidão bilateral DOM nem a troca pós-âncora pela
rede. Ele continua com `claim: None` e `materialization_scope: None`. Logo, novos
planos Bitcoin, inclusive funding/refund, recusam. Os comentários e a lista de
limites foram corrigidos para refletir essa restrição real.

Preencher apenas o scope ou usar uma janela M.8 sintética para liberar funding
não implementaria as garantias pedidas. A instalação do resultado da rodada,
o scope autenticado e a recuperação sem escalar ainda precisam chegar ao root
pelo mesmo grafo de donos. A V3 conecta componentes internos, não esse driver.
A fonte pública EVM, o refresh temporal autenticado e as rotas SOL/XMR também
permanecem pendentes.

## Relação com o objetivo 10/10

| Frente | Evidência desta entrega | Ainda necessário |
| --- | --- | --- |
| Verificação formal | Nenhuma prova formal nova | Modelos, propriedades e vínculo com a execução real |
| Validação independente | Verificadores Python de claim e mensagens; 15 testes passaram | Comparação com saídas Rust, demais pernas e revisão por outra equipe |
| Fronteiras de confiança | Binding do funding e autenticação do participante | Campanha RPC/signer/ativos/XMR comprometidos |
| Recuperação extrema | Código e teste Rust de duas retomadas físicas | Compilar/executar, varrer crashes, reorgs e fees no daemon |
| Privacidade | Frames expõem vínculo sessão/participante; não há alegação de anonimato | Modelo e experimentos de correlação entre pernas |
| Auditorias complementares | Nenhuma auditoria externa | Criptografia e execução distribuída revisadas no commit candidato |
| Operação reproduzível | ZIP cumulativo, hashes, patches e runner | Builds independentes, deployment e recuperação por outro operador |

Prioridade preservada: BTC→DOM→EVM, EVM→DOM→BTC, BTC→DOM→BTC e EVM→DOM→EVM pelo
binário real. Quantidade de testes não é porcentagem de segurança.

## Evidências observadas e entrega

Foram executados **15 testes Python, todos aprovados**. Rust não foi compilado
nem executado: as ferramentas continuam ausentes. O checker de arquitetura
`check-boundaries.sh` passou. Há uma checagem auxiliar de sintaxe por Tree-sitter,
comparada com a V2, sem expansão de macros ou checagem de tipos; ela não vale como
compilação. Os relatórios anexos identificam os arquivos por hash.

`STATUS-META-10.json` conserva as frentes e pendências. `V2-PARA-V3.patch` registra
a evolução incremental e `ALTERACOES.patch` o cumulativo desde a base oficial.
Os patches já estão aplicados. A branch é entregue com o índice atualizado,
sem novo commit ou push. V1/V2 continuam documentadas como histórico.
