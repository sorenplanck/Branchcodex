# Auditoria de abertura antecipada

**Contraexemplo reproduzido.** No perfil atual de 198 puzzles/200.000 quadraturas,
a composição sem proteção de prazo permite que A receba XMR e devolva seu DOM,
deixando B sem o output da claim DOM. Esse perfil fica rejeitado para uso como
swap seguro. Relatório: [EARLY-DOM-REFUND-REGTEST-RESULT.json](EARLY-DOM-REFUND-REGTEST-RESULT.json).

O ensaio `regtest_claim ... early-dom-refund` testa uma composição deliberadamente
sem admissão por prazo e sem scheduler de devolução XMR. Usa somente moedas
criadas em seus próprios nós offline. Não é um teste contra usuários, carteiras
existentes ou um protocolo implantado.

## Pergunta de segurança

Uma abertura que recupera a chave correta é necessária, mas não basta para
uma troca atômica. A parte que recebe a cápsula pode começar o cálculo assim
que tiver seus bytes públicos. A preparação, verificação e espera de depósito
também consomem a janela disponível. Não existe no solver um relógio que se
reinicie quando a aplicação decide iniciar a troca.

O perfil experimental fixa 200.000 quadraturas para qualquer quantidade de
puzzles. Aumentar de seis para 198 puzzles altera a amostragem de verificação;
não transforma a abertura de um puzzle em um atraso de 198 vezes esse valor.
Depois das aberturas selecionadas, uma share atrasada válida basta para
reconstruir a share do participante.

## Sequência exercida

A deposita DOM para receber XMR; B deposita XMR para receber DOM.

1. A recebe a cápsula da share DOM de B. O emissor termina e um solver separado
   recebe somente os bytes públicos. A recupera essa share **antes de financiar
   DOM**, sem enviar a share original ou os fatores RSA ao solver.
2. As duas reservas são financiadas em nós próprios. A e B entregam as duas
   pré-assinaturas adaptadoras válidas, vinculadas às transações contraparte.
3. A descarta o objeto que guardava a share original de B e usa a share
   recuperada para devolver DOM. A devolução e seu gasto posterior são incluídos.
4. A retém e completa a claim XMR que B já autorizou. O daemon inclui o pagamento.
5. A assinatura XMR observada revela o segredo correto. A claim DOM de B é
   concluída e passa na validação criptográfica, mas a admissão no nó deve
   rejeitá-la porque a reserva já foi consumida pela devolução.
6. O ensaio gasta também o output XMR recebido por A após a maturidade local.

O sucesso deste teste significa **reproduzir a perda de atomicidade** nessa
composição, não demonstrar segurança. O relatório precisa registrar isso
explicitamente. O ensaio não simula uma devolução XMR concorrente de B, prazos
seguros, reorgs ou rede pública. Portanto não refuta toda construção possível
baseada em recuperação temporizada.

```sh
cargo run --offline --locked --release \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim -j 2 -- /caminho/absoluto/monerod \
  early-dom-refund /caminho/absoluto/lhtlp-bridge 198
```

## Consequência para o mecanismo novo

Execução local: cápsula e verificação 77,581 s; verificação/abertura antecipada
14,343 s, dos quais 1,072 s no solver sequencial; total 114,373 s. DOM financiado
na altura 5, devolvido na 6, gasto posterior na 7. A recebeu e gastou depois
1 XMR de teste; a claim DOM válida de B foi rejeitada por input consumido.
Compilação excluída, mineração sob demanda. Artefatos em
`target/regtest-796560-1790447847686568602/`.

Não tratar o perfil curto de laboratório como configuração segura de swap.
Ele continua útil para validar assinaturas, serialização, abertura e inclusão.
A política real precisa de uma hipótese explícita e conservadora de atraso
adversarial, medida desde a primeira divulgação, e de margens para verificação,
financiamento, maturidade, inclusão, observação e reação. Deve também recusar
novas ofertas quando essa margem tiver acabado. Recusar todas as trocas não
cumpre a missão: o caminho permitido precisa demonstrar sucesso e recuperação.

Uma pré-assinatura entregue não pode ser revogada apagando um estado local.
Se já foi entregue, a contraparte honesta precisa continuar observando e
disputando o gasto durante a recuperação. A próxima integração deve exercitar
também essa contraparte, em ambas as ordens de inclusão, com prazos justificados.

## Relação com a pesquisa

O [PayMo, §§2.2–2.4](https://eprint.iacr.org/2020/1441.pdf) entrega o material
temporizado antes do financiamento e exige separação conservadora entre os
prazos das duas moedas. Também descreve a alternativa de cifrar a share de chave
quando os índices da transação ainda não são conhecidos. A seção 3 assume
sincronia e canais autenticados. Nossa inferência é que os benchmarks locais
de abertura e pagamento não substituem essas premissas na adaptação DOM↔XMR.
