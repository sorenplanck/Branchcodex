# Limite atual de recuperação após expiração do Relay

Este documento caracteriza o protocolo existente. Não ratifica renovação,
não altera TTL, sequência, política, DSC1, disponibilidade negociada ou L1.
Os testes abaixo estão escritos, mas não foram executados nesta entrega.

## Mensagem aceita antes de expirar

A perda de ACK não exige novo envelope. `DurableRelaySenderV1::submit_pending`
reenvia os bytes retidos; `ProductionRelayV1::submit_durable` retorna o mesmo
ACK para a mesma chave e bytes. Isso comprova armazenamento, não aceitação
pelo Contracts. O Noise também confirma armazenamento: `send_direction` /
`receive_persisted_receipt` usam a página e o cursor exatos.

Se o inbox já aceitou o envelope, `DurableRelayInboxV1::ingest_one` reconhece
a duplicata durável antes de nova autenticação. `reconstruct_transcript`
revalida o histórico com `accepted_now` realmente persistido. Não inventa
uma observação passada para aceitar uma mensagem nova.

## Mensagem nunca aceita antes de expirar

`relay::auth::accept_envelope` recusa `Expired` antes da verificação de
sequência. A quarentena preserva essa recusa; não cria um elo de transcript.
Um sucessor ainda válido encontra `SequenceGap`. `prepare_route_application`
preserva o primeiro envelope/expiry; reenfileirar a aplicação não renova nada.

Não existe certificado negativo ou operação de renovação que autorize a
substituição. Alterar expiry sob a mesma chave produz equivocation;
usar a sequência seguinte não preenche o elo ausente. `Reprocess` da
quarentena continua sujeito à autenticação; `ReleaseFailedClosed` não
concede aceitação. ACK do Relay ou recibo Noise não modifica esse resultado.

Uma recuperação versionada dessa segunda situação exige decisão normativa
explícita antes de implementação. Este documento não escolhe tal protocolo.

## Fontes e cobertura

- [F6 §5.4, §6.1 e §6.6](../normative/DOM-Interop-F6-Engineering-Specification-v1.0.md): ordem de validação, resend byte-idêntico, fluxo contíguo.
- [Fundação v0.19, §4.6 e decisões D-019/D-020/D-029](../normative/DOM-Interop-Foundation-Document-v0.19.md): chave por fluxo endereçado, registro fechado e DSC1 opaco sem autoridade econômica.
- [Teste existente de cabeça expirada](../../../crates/route-transport/tests/bridge_roundtrip.rs): `an_expired_envelope_refuses_without_poisoning_the_mailbox`.
- [Novas caracterizações](../../../crates/route-transport/tests/expiry_recovery_characterization_v23.rs): ACK perdido/reopen dos três stores, duplicata após expiry, expiry original preservado, cabeça nunca aceita em quarentena e sucessor recusado.

Os novos testes usam BIP340 real no envelope e stores reais. O payload é uma
fixture opaca de transporte, não uma assinatura econômica DSC1. O primeiro
caso usa o seam de ingestão efêmera para produzir o estado legítimo entre
persistência do inbox e ACK da página; a retomada usa a página de produção
durável. Isso não equivale a testar uma queda real do processo Noise.
