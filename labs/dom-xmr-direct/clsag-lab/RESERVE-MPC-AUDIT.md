# Reserva DOM — inspeção e evidência limitada

A integração usa o backend fixado `grin_secp256k1zkp` 0.7.15, cujo pacote
registra a revisão `15cfeedecabe30e58128d8970627919907bae0f3`, e o adaptador
DOM local para H_DOM e a faixa `(v, 2^52−1−v)`. O formato final é o mesmo
Bulletproof agregado de 739 bytes aceito pelo consenso nativo.

## Nonce comum não substitui o nonce privado

Um comentário do módulo legado `dom-scriptless-crypto/src/shared_output.rs`
afirma que conhecer o nonce comum permite recuperar a abertura inteira. Essa
afirmação não corresponde diretamente ao caminho de geração inspecionado:
`rangeproof_impl.h`, linhas 512–513 do pacote fixado, deriva `alpha/rho` do
nonce comum e `tau1/tau2` do nonce privado separado. A resposta incorpora a
abertura multiplicada pelo desafio e essas máscaras privadas. Os participantes
do novo experimento mantêm nonces privados independentes, sem publicá-los.

A distinção é discutida na [proposta original do Grin](https://github.com/mimblewimble/grin-wallet/issues/105).
O rewind legado deriva ambos os pares de um único nonce; isso não reproduz
as máscaras privadas do caminho MPC aqui usado. Essa inspeção não é prova
de segurança nem demonstra ausência de outros vazamentos. Não exercitamos
extração adversarial completa ou auditoria de side channels. O comentário
legado ficou intacto para não ampliar as alterações ao protocolo anterior.

O nonce comum continua sendo tratado como segredo: o driver deriva-o de uma
seed efêmera e do plano aprovado. No ensaio ambos os participantes simulados
recebem essa seed no mesmo processo. Um protocolo autenticado de acordo sobre
essa seed, proteção contra repetição/reinício e auditoria de participantes
maliciosos ainda faltam. A condição de uso único dos estados em memória não
substitui persistência ou proteção contra rollback.

## Ajuste mínimo da dependência

`bulletproof_mpc_round1/round2` aceitam `extra_commit` vazio, mas o finalizador
chamava incondicionalmente `bp_verify_with_extra_commit`, que o rejeita. Assim,
até uma prova plain correta falhava antes da verificação. O finalizador agora
seleciona `bp_verify` quando o campo é vazio e mantém a verificação com dados
extras quando não é. O consenso não mudou. O teste positivo de reserva plain
falhou antes da correção e passou depois; outro teste confirma que uma prova
com dados extras não valida sem eles ou com bytes diferentes.

## O que ainda falta

- Financiamento com recuperação pré-verificada e prazos coordenados nas duas
  pernas; o exemplo regtest só exerce claims cooperativas.
- Autenticação e plano completo aprovado por processos separados, sem uma
  instância controlando simultaneamente as duas partes.
- Segurança contra participantes maliciosos e reinício/fork dos estados MPC,
  além de validação da biblioteca C e de sua transcrição DOM.
- Evidência de tempo no GitHub e nas condições de rede pretendidas. Mineração
  local acelerada não demonstra o prazo máximo de uma troca em redes públicas.
