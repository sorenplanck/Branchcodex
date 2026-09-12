# V17 — construção de transações conectada ao bootstrap

Esta alteração foi escrita sobre a V16 atualizada, árvore
`4c8386f4a011240712f99cf1311bbf9cbbe9f0bb`. Não foram executados builds,
testes, scripts do protocolo ou swaps nesta entrega.

## Código entregue

- `dom-adaptor/src/bootstrap_templates_v17.rs`: cálculo do orçamento, codec
  canônico limitado das ofertas e construção dos templates nativos de
  funding, claim e refund. Os construtores existentes verificam as provas,
  estrutura e equações de balanço. Não são transações assinadas.
- `dom-actuator/src/wallet_templates_v17.rs`: composição das três shares de
  assinatura a partir das aberturas reais da carteira, das reservas, da share
  colaborativa e de offsets separados por finalidade. As shares privadas são
  opacas e não são gravadas em arquivos públicos.
- `production_run.rs` e `production_run_universal.rs`: preparação e retenção
  da oferta local antes da publicação. Reabertura reutiliza as provas exatas
  e exige correspondência com a carteira e a reserva existentes.
- `production_bootstrap_templates_v17.rs`: após a BP final, publica a oferta
  local, recebe a candidata da contraparte, monta os três templates e solicita
  ao Store o compromisso `0x0b`. A assinatura desse compromisso e o replay
  passam pelo proprietário DSC1/outbox existente. F6 aguarda ambos os
  compromissos de cada perna no perfil novo.
- `ContractsSessionStoreV1::operational_templates_complete_v17`: audita as
  duas mensagens aceitas. A fase `TemplatesCommitted` isolada não basta:
  a primeira mensagem já coloca a sessão nessa fase.
- O gate F7 para refund DOM comum reconhece a reserva de saída do perfil
  novo e exige as taxas e a forma correspondentes. Isso não instancia o
  emissor F7 nem autoriza funding antes do refund assinado.
- `import_wallet_offer_v17.py`: instalação atômica e idempotente da oferta
  pública remota, com limites, identificadores esperados e recusa de conflito.

## Perfil de termos e orçamento

O caminho novo exige `policy_version = 17` nos termos **assinados** e no
roster correspondente, além do bootstrap privado nativo montado. As duas
pernas da composição precisam concordar na versão conforme o compositor.
Não altere esse campo diretamente em um artefato já assinado: gere uma nova
sessão e todos os artefatos vinculados pelos hashes normais do projeto.

Perfis anteriores conservam sua interpretação; a V17 não migra silenciosamente
sessões antigas. O perfil 17 não demonstra que o restante da execução está pronto.

Para principal `P`, taxa recomendada de saída `E` e limite assinado `L`:

```
valor do output compartilhado = P + E
taxa de funding <= L - E
claim OU refund paga P e consome E
reserva da carteira = P + E + taxa real de funding
```

A aritmética é verificada contra overflow e limites de prova. A saída é
exclusiva: não se reservam duas taxas de saída para gastar duas vezes o mesmo
output. O prazo do refund vem dos termos; a altura de negociação vem do
checkpoint DOM da evidência temporal autenticada. Isso não substitui a
revalidação temporal imediatamente anterior ao funding.

## Troca de ofertas públicas

O transporte dessas ofertas nesta versão é por arquivos. Não há um novo
tipo de mensagem Relay nem entrega automática das ofertas via rede.

Na montagem do Stage12, antes da troca BP, cada daemon publica, no seu `state_dir`:

```
dom-wallet-offer-v17-<session_id_hex>.local
```

Transporte o arquivo público para a máquina da contraparte. No destinatário,
o instalador abaixo exige os identificadores da sessão já conhecida pelo
operador; não os obtenha cegamente do arquivo recebido:

```sh
python3 crates/dom-interopd/scripts/import_wallet_offer_v17.py \
  --source /caminho/oferta-recebida.local \
  --state-dir /caminho/absoluto/do/state-dir \
  --chain HEX64_DA_CHAIN_DOM \
  --session HEX64_DA_SESSAO \
  --terms HEX64_DOS_TERMOS_ASSINADOS \
  --peer-participant HEX64_DO_PARTICIPANTE_REMOTO
```

O instalador escreve `dom-wallet-offer-v17-<session_id_hex>.peer`, com modo
0600. O diretório deve pertencer ao operador e ter modo 0700. Faça a troca
nos dois sentidos para cada sessão; as posições da rota têm sessões distintas.
Depois da prova BP, o daemon lê a oferta nos ticks do bootstrap. Uma primeira
mensagem `0x0b` que chegue antes dos dados locais fica pendente no inbox, após
verificar identidade, sequência, predecessor e vínculo BP; os hashes dos três
templates só são aceitos depois da construção independente. A janela do envelope continua sendo a
janela já retida do bootstrap, sem prolongar os prazos do swap.

Ausência resulta em espera. Arquivo presente mas ilegível, inválido, de outra
sessão ou diferente da oferta já retida resulta em recusa. Após retenção,
reinício pode usar o journal mesmo sem o arquivo de transporte. Arquivos
`.pending` órfãos nunca são interpretados como ofertas completas.

A oferta contém dados públicos de construção. O importador Python não
verifica provas criptográficas: isso ocorre no Rust. Nem o arquivo nem o
hash impresso autorizam assinaturas de kernel ou transmissão de fundos. O
acordo autenticado sobre os templates usa os compromissos DSC1 existentes.

## Estado e limites desta entrega

O código avança a construção até o compromisso bilateral dos templates;
não conclui o bootstrap inteiro nem as 16 rotas. Permanecem necessários:

1. Autorizar no Store as chaves compostas de kernel por finalidade, com
   prova de posse e vínculo durável aos templates. A chave da share BP não
   pode ser usada como substituta da chave de funding/claim/refund.
2. Conectar essas autoridades às rodadas de refund e funding, ao emissor
   F7, à entrega da autoridade M.8 consumida e ao produtor de claim universal.
3. Implementar compensação XMR condicionada ao funding por uma regra que
   também impeça gasto fora do daemon, e concluir a execução/recuperação XMR.
   O bloqueio de funding XMR sem essa proteção permanece.
4. Automatizar a troca das ofertas públicas no transporte selecionado.

Não há executável compilado neste ZIP. Para gerar o binário no seu Linux,
com os pré-requisitos do projeto já instalados:

```sh
python3 scripts/build_daemon_v14.py \
  --output dist/v17/dom-interopd \
  --report-dir artifacts/daemon-v17-build
```

Esse comando foi incluído para execução pelo usuário; não foi executado aqui.
Relatórios de versões anteriores no repositório continuam sendo históricos
e não atestam este código.
