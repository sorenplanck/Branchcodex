# Substituição da recuperação temporizada XMR: condições de projeto

Estado em 27/09/2026: **pesquisa, não protocolo aprovado nem implementado**.
O ensaio [`FAST-RACE-AUDIT.md`](clsag-lab/FAST-RACE-AUDIT.md) mostrou que o
candidato atual não é atômico quando a share XMR é recuperada cedo e o peer
recebe os bytes completos do claim antes de sua inclusão. O relógio e o
journal honestos não impõem uma restrição ao peer nem ao consenso XMR.

## Restrição revelada pelo contraexemplo

Se (1) o adversário consegue assinar uma devolução XMR válida enquanto o
claim honesto XMR ainda pode ser divulgado, (2) os bytes desse claim revelam
o witness do claim DOM ao peer, e (3) o claim DOM independe da inclusão XMR,
então existe a ordem: divulgar bytes → incluir devolução XMR → rejeitar
claim XMR → incluir claim DOM. A segurança exige eliminar ao menos uma dessas
três condições por uma restrição **de consenso ou criptográfica**. Política
local, journal, consulta de key image livre e espera em um único daemon não
eliminam essa ordem; a corrida nativa confirmou isso para o perfil atual.

## Referências e consequência para DOM

As [premissas do Farcaster](https://github.com/farcaster-project/RFCs/blob/main/00-introduction.md)
separam a chain que arbitra com lock/refund temporal da chain sem scripts,
como Monero. O [protocolo de Athanor](https://github.com/AthanorLabs/atomic-swap/blob/master/docs/protocol.md)
usa um estado `Ready` e caminhos `Claim`/`Refund` excludentes no contrato da
chain que arbitra; ele também explicita a corrida de segredos divulgados antes
da confirmação. O [trabalho de Gugger](https://github.com/h4sh3d/xmr-btc-atomic-swap)
e a [explicação do COMIT](https://arxiv.org/abs/2101.12332) mostram por que
a chain sem scripts não precisa carregar o timelock quando a outra chain
fornece a arbitragem. São lições de estrutura, não prova para DOM.

O consenso DOM presente em
[`transaction.rs`](../../crates/dom-consensus/src/transaction.rs) reconhece
somente kernels `PLAIN`, `COINBASE` e `HEIGHT_LOCKED`. A reserva DOM do
laboratório recebe uma devolução pré-assinada por altura, mas não tem um
estado nativo `Ready` nem um output que aceite caminhos `Claim` e `Refund`
mutuamente exclusivos por fase. Adicionar flags no daemon não criaria essa
exclusão perante um peer adversário. Reproduzir a construção de arbitragem
exige desenhar e validar uma **nova regra de consenso DOM**, ou demonstrar
outra primitiva existente com garantia equivalente. Isso é uma dependência
real da nova perna DOM↔XMR, não uma mudança automática autorizada para outras
pernas.

## Candidato a testar, sem cápsula de tempo

Uma direção é uma reserva XMR com chave combinada de duas shares, sem
devolução XMR pré-assinada que possa vencer antecipadamente. Um único
compromisso DOM de arbitragem teria duas fases: antes de `Ready`, o dono DOM
pode recuperar DOM somente expondo a share que permite ao dono XMR recuperar
XMR; depois de `Ready`, o dono XMR pode receber DOM expondo sua share, que
permite ao dono DOM receber XMR. Se não houver claim, o refund DOM posterior
também expõe a share necessária à recuperação XMR. A transição `Ready` só
pode ocorrer após a reserva XMR correta estar confirmada e utilizável.

Essa descrição **não resolve sozinha** a corrida na borda do prazo: um claim
DOM que divulga a share no mempool e perde para um refund pode permitir que
um lado receba os dois ativos. Antes de qualquer funding, o desenho precisa
especificar janelas sem sobreposição, limites de inclusão/observação,
tratamento de reorg, chave XMR e campos de consenso completos; depois deve
enumerar escalonamentos adversariais e testar as transações nos daemons.
Se a margem requerida ultrapassar a meta aproximada de 2–3 minutos, registrar
isso como inviabilidade da meta sob essas hipóteses. Não esconder espera de
maturidade XMR nem introduzir custódia, pré-funding obrigatório ou BTC.

## Próxima evidência necessária

1. Modelar os estados e eventos `Ready`, `Claim`, `Refund`, divulgação de
   shares, inclusão e reorg, com busca por contraexemplos de dupla captura.
2. Confirmar o formato de compromisso e verificação que o consenso DOM teria
   de oferecer; separar mudanças de consenso das APIs do daemon.
3. Só implementar funding depois de a máquina de estados excluir a corrida
   observada, com premissas temporais declaradas e defensáveis.
4. Medir sucesso e recuperação com participantes independentes e os daemons
   reais, incluindo confirmação e maturidade exigidas, antes de afirmar prazo.
