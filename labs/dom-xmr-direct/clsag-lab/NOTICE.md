# Origem e escopo

O layout do transcript CLSAG e suas equações foram adaptados de
[monero-oxide, monero-clsag](https://github.com/kayabaNerve/monero-oxide/tree/c8be5d3d1287669946a83fbfcb296ce2a8852e47/monero-oxide/ringct/clsag),
fixado em `c8be5d3d1287669946a83fbfcb296ce2a8852e47`, a mesma revisão já
presente no Cargo.lock do projeto de origem. Sua licença está preservada em
`LICENSE-MONERO-OXIDE`. A adaptação experimental de nonce e sua prova de
igualdade não são funcionalidades atribuídas ao upstream.

As derivações de outputs padrão em `src/native.rs` seguem também o módulo
`SharedKeyDerivations` de `monero-wallet/src/lib.rs` na mesma revisão e licença.
O construtor de transações, scanner, Bulletproofs+ e operações de assinatura
conjunta são dependências inalteradas. `src/joint.rs` adapta o protocolo que
essas operações compõem; o upstream não deve receber atribuição de uma prova
de segurança do adaptador DXP1.

O verificador final e o hash-to-point são dependências upstream não modificadas.
Não se usa o verificador experimental de pré-assinatura como único oráculo
para declarar uma assinatura final válida. Isso não equivale a validação de
uma transação completa por um daemon Monero.

`src/dom_joint.rs` usa duas contribuições de nonce e fatores vinculados à
lista ordenada de compromissos, seguindo a estrutura discutida nas seções
4.1, 4.4, 5 e 7.3 do [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html).
É implementação própria sobre primitivas DOM, com shares aditivas 2-de-2,
provas de posse, binding do corpo e ponto adaptador. O desafio e o formato
final são nativos DOM. Não é implementação de uma ciphersuite do RFC, nem
atribui ao RFC uma prova de segurança dessa adaptação ou da recuperação DXP1.
