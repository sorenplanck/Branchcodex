# V13 — montagem do bootstrap e estado de implementação

Esta versão é um **checkpoint de desenvolvimento**, não uma V13 homologada.
O comando novo, a custódia e a ligação às etapas 10/12 foram escritos. Os testes
Rust novos ainda precisam ser compilados e executados; não foi demonstrada a
inicialização completa do binário com todas as dependências de uma rota.
A compensação segura e o claim completo continuam pendentes.

## Código novo do bootstrap

`dom-interopd bootstrap-v13` executa uma cerimônia de preparação independente
de clientes BTC, EVM, SOL ou XMR. Cada participante fornece somente suas
credenciais Relay das pernas em que participa, além da senha da própria
identidade Contracts. A DOM e as autoridades assinadas continuam obrigatórias.

O comando autentica o registry corrente, seus signatários, os termos, o roster
e a identidade DOM; gera a contribuição privada de cada posição em um cofre
nativo; troca compromissos e assinaturas; vincula a cápsula de recuperação às
shares; publica o artefato bilateral consumido pelo verificador já existente.
Não produz transações de funding, claim ou compensação.

A ordem é: quatro offers → quatro assinaturas do compromisso global → quatro
revelações públicas de contribuição → quatro assinaturas da revelação global
→ artefato final. As posições 0/1 são o roster ordenado upstream; 2/3 são o
roster ordenado downstream. Uma pessoa pode ocupar uma ou duas posições.
`reveal` designa a contribuição pública da cápsula; não é T, U ou o blinding
privado da saída compartilhada.

Os arquivos públicos são duravelmente retidos antes da publicação. Uma
publicação parcial retoma somente o prefixo exato desses bytes. Mensagem
pendente aparece em `awaiting`; mensagem trocada, truncada ou de outra sessão
é erro. Assinaturas já publicadas são reutilizadas byte a byte.

A preparação tem lock exclusivo próprio, inclusive antes de criar seu banco.
Cofres vazios são construídos numa área privada e publicados atomicamente,
antes de receber qualquer share. Uma construção interrompida nessa área é
preservada em quarentena; ela nunca é fonte de uma autoridade operacional.
Depois da publicação de um offer, a falta de cofre, journal ou share é recusa;
não há criação de uma nova share como recuperação de uma já publicada.

## Ligação ao binário real

O caminho configurado deve terminar exatamente em
`contracts-bootstrap-v13.bin`. Esse nome reserva a seleção do perfil V13:
retirar o plano ou os cofres não permite uma retomada silenciosa pelo legado.

As duas composition roots passam o caminho à etapa 10. Após conferir o genesis
DOM e abrir a identidade nativa, ela reabre o plano retido, autentica o registry
histórico exato, verifica novamente o artefato e compara as duas bindings com
as autoridades reais de `ProductionChainSignerAuthoritiesV1`. Reabre os
cofres e journals sem criação, recupera as capacidades e confere share pública
e cápsula contra o artefato assinado. A etapa 12 recebe e mantém esses donos
privados pelo tempo de vida do Relay.

Isso não elimina as demais exigências nativas de DOM wallet, F6, Bulletproof,
refund, readiness, âncoras ou assinatura por finalidade. Passar esta cerimônia
não substitui a admissão da rota e não demonstra que essas fases posteriores
estejam completamente produzidas e conectadas.

## Preparação no ambiente do operador

Linux, toolchain Rust do repositório e dependências nativas são necessários.
Use dados de teste e preserve a custódia de cada participante separadamente.
Os comandos abaixo usam caminhos ilustrativos; substitua-os pelos seus.

Primeiro execute a validação da entrega:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v13.py
```

O runner mantém as verificações anteriores, inclui os testes Rust do novo
módulo no pacote `dom-interopd` e compila o binário de produção. Para executar
somente a cerimônia nativa de teste:

```bash
cargo test --locked -p dom-interopd --no-default-features --features production \
  production_contracts_bootstrap::producer_v13 -- --nocapture
cargo build --locked --release -p dom-interopd --no-default-features \
  --features production --bin dom-interopd
```

A identidade Contracts, registry assinado, termos, roster e política de budget
já devem existir. O comando não substitui identidades já vinculadas aos termos
nem cria chaves para outras pessoas. Arquivos de entrada: proprietário atual,
modo 0600, sem links; diretórios: 0700. Os caminhos do plano são absolutos e
canônicos. O diretório de trabalho deve estar dentro do `state-dir` utilizado
pelo daemon.

Exporte o plano público da configuração existente:

```bash
install -d -m 700 /CAMINHO/state/inputs/ceremony-v13
python3 crates/dom-interopd/scripts/bootstrap_v13.py plan \
  --manifest /CAMINHO/state/bootstrap-create-v11.conf \
  --state-dir /CAMINHO/state \
  --participant ID_DOM_DO_PARTICIPANTE_EM_64_HEX_MINUSCULOS \
  --output /CAMINHO/state/bootstrap-plan-source-v13.json
```

O helper entende a configuração universal V11 e seu conteúdo comum V6, além
das famílias V5–V10. Apenas prepara referências; o Rust autentica seu conteúdo.
Nenhum recurso operacional BTC/EVM adicional é incluído no plano.

Forneça por stdin privado um JSON com estas chaves:

```json
{
  "identity_passphrase": "SENHA_DA_IDENTIDADE_CONTRACTS",
  "upstream_relay_secret": "CHAVE_LOCAL_UPSTREAM_EM_64_HEX_MINUSCULOS",
  "downstream_relay_secret": "CHAVE_LOCAL_DOWNSTREAM_EM_64_HEX_MINUSCULOS"
}
```

Na perna em que a pessoa não participa, use `null`. Quem participa das duas
usa chaves Relay distintas. O leitor limita o documento a 16 KiB, mantém seus
campos emprestados de memória apagável e recusa sequências JSON com escape.
A senha utilizada aqui deve ser a mesma fornecida ao runtime. Não coloque
esse JSON no diretório compartilhado nem em argumentos de linha de comando.

```bash
./target/release/dom-interopd bootstrap-v13 \
  --plan /CAMINHO/state/bootstrap-plan-source-v13.json \
  --work-dir /CAMINHO/state/inputs/ceremony-v13 \
  < /CAMINHO/PRIVADO/bootstrap-credentials.json
```

Repita o comando após receber os arquivos de `awaiting`. Troque somente os
arquivos públicos `offer-N.bin`, `commit-signature-N.bin`, `reveal-N.bin` e
`reveal-signature-N.bin`, preservando proprietário e modo 0600 no destino.
Não copie bancos, cofres, quarentenas, plano retido ou credenciais para o par.
Cada participante mantém suas próprias paths e sua própria custódia.

Quando o relatório indicar `stage: complete`, ambos devem obter os mesmos
commit/reveal digests e o mesmo artefato final. `funding_authorized` continua
`false`: a autorização de funding pertence à admissão/execução nativas.

O helper também produz **novas cópias** das configurações com os dois digests
e o caminho V13. Ele não sobrescreve o original nem altera as referências às
chains selecionadas:

```bash
python3 crates/dom-interopd/scripts/bootstrap_v13.py seal \
  --manifest /CAMINHO/state/bootstrap-create-v11.conf \
  --state-dir /CAMINHO/state \
  --work-dir /CAMINHO/state/inputs/ceremony-v13 \
  --output /CAMINHO/state/create-with-bootstrap-v13.conf
python3 crates/dom-interopd/scripts/bootstrap_v13.py seal \
  --manifest /CAMINHO/state/bootstrap-reopen-v11.conf \
  --state-dir /CAMINHO/state \
  --work-dir /CAMINHO/state/inputs/ceremony-v13 \
  --output /CAMINHO/state/reopen-with-bootstrap-v13.conf
```

Use essas configurações somente na criação de uma nova instância de teste.
Uma instância já provisionada está vinculada aos digests de suas configurações:
não há migração automática para mudar essas bindings ou transportar cofres
existentes para outra sessão. O helper calcula compromissos de bytes; somente
o leitor nativo do daemon aprova assinaturas e autoridades.

## Evidências e limites

Foram escritos testes Rust de publicação em todos os cortes de prefixo,
concorrência, ausência versus substituição, links, limites de stdin, quatro
assinaturas por estágio, cerimônia com dois participantes e cofres reais,
retomada e montagem, perda de custódia e preparação vazia interrompida.

Os testes Python verificam o preparador de planos e configurações, incluindo
modo de reabertura, wrapper universal, preservação dos recursos externos,
digests, links, paths inválidos e recusa de sobrescrita. Não simulam sucesso
de um swap nem substituem os testes Rust.

Não houve compilação Rust ou swap real neste ambiente. Consulte o relatório
do runner no ZIP e `STATUS-V13.json`; os três requisitos completos ainda não
estão comprovados nem devem ser tratados como concluídos.
