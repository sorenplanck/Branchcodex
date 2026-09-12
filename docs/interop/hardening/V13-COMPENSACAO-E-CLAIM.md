# V13 — compensação e claim: alterações e pendências

## Segunda tarefa: compensação sem funding XMR

A V13 impede novas assinaturas de compensação ordinária pelo produtor nativo
`XmrOrdinaryRecoveryRoundV12::begin`. A recusa ocorre antes de tratar nonces.
O driver de assinatura/Relay também recusa essa finalidade antes de criar ou
retomar a sessão de assinatura. O driver de custódia recusa a criação e a
retomada de pré-funding desse grafo. Cancelamento ordinário continua disponível;
os leitores históricos permanecem para inspeção e recuperação.

**Isso é contenção, não uma compensação funcional corrigida.** A V13 não
revoga transações assinadas anteriormente, não transforma saldo/txid consultado
por RPC em prova de consenso e não habilita XMR no runtime. O teste adversarial
novo demonstra que a validação de uma compensação antiga não depende de
qualquer funding Monero: dado o input DOM previsto, assinatura e altura bastam.
Esse teste Rust foi escrito, mas não executado localmente.

A substituição precisa mudar o mecanismo que autoriza gastar DOM: a condição
deve vincular sessão, termos, funding XMR, endereço compartilhado, quantia e
finalidade. Assinar depois de observar funding recoloca a dependência da outra
parte justamente no intervalo em que ela pode desaparecer. Assinar antes sem
condição reproduz o ataque. Nem txid exato, hash de bytes de uma transação ainda
não incluída, relógio, margem, criptografia do arquivo ou consenso de RPCs no
daemon resolve o envio direto à chain.

Não foram acrescentados signatários/oráculos de confiança silenciosamente,
nem uma regra de consenso que alegue validar Monero sem implementá-lo. A
condição verificável de funding e suas premissas de consenso/disponibilidade
continuam sendo trabalho protocolar pendente.

## Terceira tarefa: finalização do claim no runtime

A inspeção confirmou quatro lacunas concretas, ainda sem implementação nova:

1. `ProductionDomClaimRuntimeV12` termina na pré-assinatura autenticada. Seu
   `finish` não adapta, persiste, transmite ou admite a transação final.
2. `ProductionF7RuntimeV12` ainda não tem seu ciclo completo de construção e
   chamadas instalado na root universal. A custódia compartilhada V13 resolve
   parte dos materiais privados; não produz automaticamente a share de gasto
   específica de payout, input e offset.
3. `ConcreteProductionDomActionAuthorityV1` recusa `Unattempted`. A materialização
   do child usa `bind_final_claim_settlement_child_v2`, enquanto a exposição e
   o transporte 0x12 recebem `ConsumedClaimSigningAuthorizationV2`. Essa
   autoridade não pode ser fabricada a partir de um digest F7 universal.
4. O stream secreto operacional atual não fornece uma custódia nativa do T
   privado de origem para essa finalização. O vault de segredos já públicos
   não pode ser usado para classificar antecipadamente o segredo como exposto.

O fluxo a implementar precisa manter: autorização F7 atual → share correta
para ClaimAdaptor → assinatura bilateral → segredo de origem ou revelação
validada → adaptação nativa → intenção e exposição duráveis → tentativa
registrada → RPC → admissão → 0x12. O reinício deve reemitir somente os bytes
retidos, preservando a exposição diante de falha de RPC ou reorg.

Nenhum desses passos foi substituído por callback que aceite bytes livres,
flag de sucesso, segredo público fabricado ou autorização BTC numa perna sem
BTC. Este checkpoint não anuncia a terceira tarefa concluída.
