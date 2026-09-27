# Contraparte devida: envio sem resposta

`counterpart_delivery.rs` registra a transação exata da contraparte depois de
verificar a primeira perna paga. É parte do mecanismo novo DOM↔XMR. O gate
da primeira liberação continua separado: a expiração desse gate não cancela
uma obrigação já iniciada.

O registro conserva bytes completos, digest do manifesto original, digest da
primeira claim observada, bloco/altura dessa observação e cadeia de destino.
Ele nasce exclusivamente, com modo 0600 e sincronização do arquivo/diretório.
Um evento de exposição possível é sincronizado **antes** de devolver os bytes
para envio. Erro de gravação inutiliza o handle. Reabrir sincroniza novamente;
arquivo ausente, parcial, corrompido ou com binding diferente não é reparado
nem recriado automaticamente. O lock exclusivo impede handles concorrentes.

O manifesto dos modos de retomada agora também é persistido antes da primeira
claim: operação, digests dos dois envelopes, vínculo da cápsula, instante
original, limites assumidos, ordem e custos das duas pernas. O journal inicial
continua vinculado à mesma operação/janela; o journal da contraparte inclui
o digest desse manifesto. O pai ainda conserva os digests esperados e a
verificação da inclusão. Não há ainda registro global que reconstrua toda a
operação ao reiniciar o coordenador antes de funding/disclosure.

## Consulta nova antes de qualquer tentativa

| Observação recebida do adaptador de cadeia | Decisão |
| --- | --- |
| Erro RPC, visão parcial ou estado desconhecido | Continuar reconciliação; não enviar |
| Transação exata no mempool | Acompanhar o pool; não reenviar |
| Transação exata em bloco canônico | Acompanhar inclusão; não declarar finalização permanente |
| Transação ausente **e** input não gasto, em snapshot coerente | Permitir somente os mesmos bytes, mantendo exposição possível |
| Gasto conflitante identificado | Resolver conflito; não gerar outra assinatura |

`Observation` é um resultado que o chamador deve verificar, não uma prova
autenticada pelo journal. `not found` isolado não satisfaz ausência com input
não gasto. Os parâmetros de cadeia e digest da transação são conferidos em
toda chamada. Não há cache de inclusão tratado como final: após reabrir, uma
consulta falha volta a exigir reconciliação. Reorg não apaga exposição possível.
O journal não aprova refunds, novo preço, mudança de destinatário ou fee bump.

## Ensaio nativo de perda da resposta

Os modos `direct-pair-xmr-first-ack-loss` e
`direct-pair-dom-first-ack-loss` incluem a retomada de claim já descrita em
`CLAIM-RESUME.md`. Depois, um terceiro processo abre o journal da contraparte,
persiste exposição e entrega os bytes por uma ponte TCP exclusivamente
loopback, com token efêmero e payload limitado/conferido.

O pai encaminha a transação exata à admissão nativa: monerod externo próprio
para XMR, ou NodeHandleImpl sobre o DomNode próprio para DOM. **Somente após
essa admissão**, fecha a conexão sem devolver confirmação ao emissor. O
processo emissor encontra EOF e encerra com exit 74, sem receipt e sem executar
destructors. O pai reabre o journal, primeiro conserva o estado desconhecido,
consulta o pool nativo e acompanha a inclusão posterior. Não despacha retry
enquanto a transação está no pool e não recria a assinatura.

Para XMR, o teste consulta `get_transactions` e `is_key_image_spent` antes do
envio, e `get_transactions` depois. Para DOM, consulta o pool e o UTXO antes,
e o pool após admissão. São nós isolados próprios sem outro produtor nessa
fase: isso não implementa um adaptador de snapshots atômicos contra um nó
hostil. O bloco/altura e o corpo exato são verificados antes de registrar a
observação de inclusão. O teste DOM preserva seu replay diagnóstico **depois
da confirmação** para conferir idempotência nativa; esse replay não é retry
do controlador enquanto a operação está pendente no pool.

Não é uma queda do monerod nem do coordenador inteiro. A resposta omitida é
da ponte para o emissor, depois de o pai receber sucesso da admissão nativa.
Não se presume que uma transação rejeitada pelo nó tenha sido retransmitida.
Os dois nós, o pai e seus dados de aprovação continuam vivos nesse ensaio.

## Limites e reprodução

O armazenamento pressupõe diretório/dispositivo confiáveis. Checksum não
autentica um escritor local hostil; rollback de backup com remoção de evento
completo exige defesa externa. O estado da obrigação ainda é criado depois
da primeira inclusão: falha antes desse ponto exige reconstrução do manifesto,
envelopes e cadeia, ainda não implementada no coordenador completo.

O teste de mudança de observação/reorg é de estado local, não um reorg nativo
produzido contra mineradores concorrentes. Segurança criptográfica e limites
temporais adversariais continuam em aberto; tempos regtest não são SLA real.

```sh
cargo test --offline --release --locked --lib --test counterpart_delivery -j2
cargo build --offline --release --locked --example regtest_claim -j2
target/release/examples/regtest_claim /caminho/monerod \
  direct-pair-dom-first-ack-loss /caminho/direct-dlog-bridge
```

Trocar para `direct-pair-xmr-first-ack-loss` exercita a ordem inversa.

## Evidência desta etapa

`COUNTERPART-DELIVERY-CHECKS.json` registra **49 testes aprovados**, Clippy
all-targets com `-D warnings` e build separado. Os seis testes novos do
journal cobrem bytes imutáveis após envio ambíguo, mudança de observação,
binding incorreto, registro parcial/corrompido, exclusão de handles concorrentes
e erro real de escrita por descritor sem permissão de gravação. Mudança de
observação após inclusão não restaura privacidade nem reutiliza a inclusão
anterior quando a nova consulta falha.

`DIRECT-PAIR-XMR-FIRST-ACK-LOSS-*` passou em **171,713 s** totais, com ambas
as claims incluídas em **83,788 s**. O trecho da contraparte sem confirmação
ao emissor consumiu **0,166 s**; o emissor encerrou com 74. O journal reaberto
foi reconciliado com pool e bloco nativos, sem retry enquanto pendente nem
nova assinatura. Outputs DOM, pagamento XMR e troco foram gastos e a devolução
DOM conflitante foi rejeitada na altura 215. Resultado, fases, watchdog e
hashes estão preservados no prefixo indicado.

`DIRECT-PAIR-DOM-FIRST-ACK-LOSS-*` passou em **168,896 s**, com claims em
**82,681 s** e trecho sem confirmação em **0,301 s**. O monerod admitiu XMR,
o emissor encerrou com 74 sem resposta e o journal reaberto acompanhou pool
e bloco; todos os outputs foram gastos. A devolução DOM perdeu na altura 214.
Os hashes dos dois conjuntos conferem com fontes e binário desta etapa.
São tempos locais com moedas regtest; não demonstram um prazo adversarial
ou a segurança completa do protocolo. Nenhuma compilação correu em paralelo.
