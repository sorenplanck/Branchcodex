# Retomada da contraparte depois da primeira claim

Esta etapa separa o contexto de uma claim já assinada dos materiais privados
usados na rodada de assinatura. O mecanismo continua sendo o experimento
novo DOM↔XMR; não modifica o executor antigo nem as outras pernas.

## Registros de retomada

`PreparedClaim::into_claim_envelope` consome a preparação XMR e descarta
`InputOpening`, que contém abertura do input e máscara do pseudo-output.
O novo `XmrClaimEnvelope` conserva somente o corpo da transação, contexto
de verificação e adaptor já validado. Seus métodos completam, verificam e
extraem essa claim; não oferecem nova rodada de assinatura. Os métodos antigos
de `PreparedClaim` usam o mesmo verificador interno para preservar as regras.

O formato XMR inclui uma transação de formato nativo com a **pré-assinatura**
CLSAG. Esses bytes ainda não são um gasto válido. Isso permite uma leitura
nativa completa sem depender dos placeholders incompletos do builder. O
formato DOM conserva o corpo de claim plain, chain ID, pré-assinatura e pontos
públicos de nonce/adaptor. Não suporta transformar a devolução por altura em
claim plain.

Ambos os formatos têm versão, tamanho limitado a 64 KiB, digest fixado pela
operação original e roundtrip canônico. A leitura XMR revalida pontos, escalar,
ring de 16 membros, único input, dois outputs, timelock, key image, pseudo-output,
hash de assinatura, prova de faixa, balanço e equação do adaptor. A leitura DOM
refaz as verificações do corpo e da pré-assinatura, vinculadas à chain ID.
O digest esperado deve vir do estado aprovado antes da falha. Calcular um novo
digest do próprio arquivo após o reinício não autentica o pagamento.

Esses registros não contêm shares privadas, nonces escalares, outgoing view key
nem o witness original. Contudo revelam o membro real do ring e a ligação entre
transações: são metadados privados dos participantes, não documentos públicos.
O experimento usa diretório 0700, arquivos exclusivos 0600 e sincronização de
arquivo/diretório antes da primeira claim. Não há pretensão de resistência a
um operador local hostil, rollback de backup ou apagamento seguro de memória.

## Queda e novo processo

Os modos `direct-pair-xmr-first-resume` e `direct-pair-dom-first-resume`
persistem os dois registros antes da primeira liberação. O registro durável
de exposição descrito em `INITIAL-RELEASE-JOURNAL.md` continua em uso.

Após incluir a primeira claim, o pai descarta os objetos originais de claim
e o witness original. Um processo novo carrega os registros e encerra com
exit 73, sem executar destructors ou produzir a contraparte. Outro processo
novo lê os mesmos registros e a transação nativa observada, extrai o segredo,
completa a claim oposta e grava seus bytes. Nenhum deles recebe chaves de
assinatura, InputOpening, nonces secretos ou o witness original.

O pai confere a transação devolvida contra os registros restaurados e a envia
à validação nativa. A inclusão, os gastos posteriores e a rejeição da devolução
conflitante continuam sendo verificados. Todo esse trabalho entra no tempo do
ensaio, inclusive sincronização, validações repetidas e ambos os processos.

**Limite da evidência:** os nós e o coordenador pai permanecem em execução.
O pai verifica a inclusão canônica e conserva os digests aprovados; os workers
validam criptograficamente os bytes fornecidos e não consultam as cadeias de
forma independente. O controle de queda ocorre depois de ler os registros,
antes de completar a contraparte. Não cobre queda após envio ambíguo da
contraparte ou reinício completo do coordenador, wallets, solver e daemons.

O gate da primeira liberação não é aplicado ao pagamento já devido. Para um
executor completo ainda é necessário persistir manifestos/digests, sessões e
obrigações antes do funding/disclosure, reconciliar ambas as cadeias após falha,
preservar exposição mesmo após reorg e controlar retransmissão de bytes exatos.
Os limites temporais e a segurança da cápsula permanecem condicionais.

## Reprodução

```sh
cargo test --offline --release --locked --test native --test native_legs -j2
cargo build --offline --release --locked --example regtest_claim -j2
target/release/examples/regtest_claim /caminho/monerod \
  direct-pair-dom-first-resume /caminho/direct-dlog-bridge
```

Trocar para `direct-pair-xmr-first-resume` exercita a ordem inversa. As moedas
são criadas somente em nós locais próprios e offline. A opção interna
`--claim-resume-worker` não é um RPC nem uma API de publicação.

## Evidência

`CLAIM-RESUME-TESTS.json` registra **43 testes aprovados**, incluindo nove de
claims XMR (quatro novos testes de retomada), dois de claims nativas DOM,
11 do registro durável de exposição e as regressões de vínculo/prazos/cliente.
O helper de crash do journal continua sendo lançado pelo teste pai, apesar de
aparecer como ignorado na listagem principal. Clippy all-targets passou com
`-D warnings`.

Os testes novos restauram a claim XMR nos índices reais 0, 7 e 15, conferem a
mesma transação após descartar a preparação e completam ambas as direções sem
o witness original. Cada byte alterado e truncamento é recusado contra o
digest aprovado. Mutações com digest recalculado também exercitam revalidação
de ring, contexto, mensagem, pré-assinatura, corpo e comprimento. Um registro
válido de outro pagamento não é aceito sob o digest original.

`DIRECT-PAIR-XMR-FIRST-RESUME-*` passou em **170,142 s** totais, com claims
incluídas em **83,299 s**. Os dois workers encerraram com 73 e 0; restauração,
queda, novo processo e produção da contraparte consumiram **0,321 s**. DOM,
pagamento XMR e troco foram gastos, e a devolução DOM foi rejeitada na altura
214. Resultado, fases, watchdog e hashes preservados. Compilação fora do
ensaio; os tempos incluem preparação e verificações posteriores.

`DIRECT-PAIR-DOM-FIRST-RESUME-*` também passou: **171,024 s** totais,
claims incluídas em **83,683 s**, workers em **0,289 s**, devolução DOM
conflitante rejeitada na altura 215. A transação XMR efetivamente publicada
veio do worker restaurado. Os hashes dos dois conjuntos correspondem ao
binário e fontes desta etapa; os processos terminaram. Esses resultados não
estabelecem segurança adversarial, prazo de mainnet ou restart completo.
