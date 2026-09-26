# Variante com devolução DOM por altura

A auditoria anterior demonstrou que entregar cedo a share da reserva DOM permite
criar uma devolução plain e ganhar o conflito contra a claim da contraparte.
Esta variante **não gera nem entrega uma cápsula da share DOM**. Entrega somente
uma transação de devolução pré-assinada, cujo kernel nativo exige uma altura mínima.
As shares da reserva continuam separadas entre os participantes.

## Garantia usada

O consenso DOM existente inclui `features`, taxa e `lock_height` na mensagem
Schnorr do kernel e verifica a altura na validação da transação. Não alteramos
essas regras. `PreparedDomClaim::new_height_locked_refund` congela uma transação
de um input/output/kernel com a altura exata aprovada, preservando os testes
de forma, prova de faixa e balanço. O construtor plain continua rejeitando
kernels travados. Alterar a altura ou converter a devolução assinada em plain
invalida sua assinatura; os testes cobrem essas tentativas.

O helper conhece o compromisso da reserva antes de financiá-la, constrói a
devolução e usa a assinatura conjunta DOM já implementada. Para verificar a
assinatura ainda fora da cadeia, fornece um contexto com a altura futura
declarada. Esse contexto não é enviado ao nó como autorização: na admissão,
o nó verifica sua própria altura e rejeita a transação prematura.

Isso é diferente de entregar a chave e pedir que seu dono espere. O recebedor
da devolução não recebe a share da outra parte. Se a share for divulgada por
outro caminho, a proteção deixa de valer, pois uma nova transação plain pode
ser assinada. As chaves também devem ser exclusivas a essa reserva.

## Evidência local

`examples/dom_height_refund.rs` executa duas cadeias DOM regtest independentes:

- Abandono: a devolução é assinada antes do financiamento, os objetos com as
  shares/chaves originais são descartados e o nó rejeita o mesmo corpo assinado
  em todas as alturas anteriores à 12. Após chegar à altura 12, aceita a
  admissão; a inclusão acontece na 13 e o gasto posterior na 14.
- Pagamento: a claim é incluída na altura 6 e seu output gasto na 7. Mesmo
  depois da altura 12, o nó rejeita a devolução por input consumido.

[Relatório](DOM-HEIGHT-REFUND-REGTEST-RESULT.json): 30,618 s para os dois
cenários, sem compilação. Blocos são minerados sob demanda. Altura 12 é um
parâmetro deste regtest; não representa uma conversão para segundos na rede.

```sh
cargo run --offline --locked --release \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example dom_height_refund -j 2
```

O executor bilateral aceita `height-xmr-first` e `height-dom-first`. Cada modo
prepara a devolução DOM antes do depósito, verifica sua rejeição prematura,
executa as duas claims e gastos posteriores e verifica a rejeição da devolução
DOM após a claim. Essas execuções não integram ainda a recuperação XMR.

Ambos passaram: [XMR→DOM](HEIGHT-XMR-FIRST-REGTEST-RESULT.json) em 34,681 s
e [DOM→XMR](HEIGHT-DOM-FIRST-REGTEST-RESULT.json) em 34,943 s. Incluem preparação,
gastos posteriores e a checagem da devolução vencida; excluem compilação.
Mineração local sob demanda, com os dois ensaios executados simultaneamente.
Construção das claims até inclusão nas duas cadeias: 2,250 s e 2,171 s,
respectivamente. Os relatórios mantêm `atomic_swap: false`.

```sh
cargo run --offline --locked --release \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim -j 2 -- /caminho/absoluto/monerod height-xmr-first
cargo run --offline --locked --release \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim -j 2 -- /caminho/absoluto/monerod height-dom-first
```

## O que permanece sem prova

O bloqueio nativo resolve apenas a disponibilidade antecipada **da devolução
DOM pré-assinada** nesta variante. Não corrige a abertura antecipada da cápsula
XMR, nem garante uma separação segura entre seu prazo e a altura DOM.
Ambas as claims continuam válidas se já foram divulgadas: chegar à altura de
devolução não as revoga. Persistência, preparação autenticada, reorgs e disputa
conjunta entre claims/refunds permanecem necessários. O setup dos ensaios é
centralizado e o par completo ainda não tem uma prova de atomicidade.

A [auditoria temporal](../TIMING-BOUND-AUDIT.md) deriva uma restrição inferior
condicional das regras de timestamp DOM e distingue o solver adversarial do
honesto. `time_bounds` implementa essa conta sem usar a média dos blocos como
garantia. Exige âncora que permaneça na cadeia e limite de erro de relógio;
não prevê a chegada à altura nem fornece as hipóteses de tempo XMR ausentes.
