# Recuperação XMR após uma primeira abertura inválida

Continuação do trabalho de prazos conservadores em `../TIMING-BOUND-AUDIT.md`.
O mecanismo em desenvolvimento é a nova perna DOM↔XMR. Este ensaio exercita
somente a recuperação XMR; não valida a atomicidade do par.

## Caso adversarial

O desafio de cut-and-choose não garante que a primeira share atrasada seja
correta. A prova de faixa do backend também não a vincula, sozinha, ao
polinômio Feldman. Antes desta correção, o cliente resolvia apenas o primeiro
índice: uma abertura incompatível abortava a recuperação mesmo havendo outras
shares corretas disponíveis.

O novo modo `regtest_claim ... xmr-recovery-bad-first` adiciona um ao escalar
do puzzle 1 **antes** de gerar a oferta pública. Os compromissos Feldman ficam
inalterados. O produtor gera setup, ciphertexts e prova de faixa reais; só
então o cliente deriva o desafio sobre os bytes públicos exatos.

Se o índice 1 for escolhido para abertura imediata, Feldman rejeita a oferta
antes do financiamento. O experimento permite até 16 ofertas novas, contando
esse custo na preparação, sem editar um desafio existente. Quando o índice 1
fica entre os atrasados, ele é o primeiro na ordem crescente. Todas as
aberturas imediatas são corretas e verificadas por um processo público.

O produtor termina, a reserva é financiada e a chave original do participante
ausente é descartada. Cada solver recebe apenas os bytes públicos e um índice.
A primeira abertura falha em Feldman; a segunda passa, permite reconstruir a
share correta e assinar a devolução. Os dois outputs dessa devolução são gastos
em uma transação posterior, após maturidade minerada localmente.

## Alteração e verificação

`examples/support/recovery_bridge.rs` conserva o plano verificado e busca
somente nos índices atrasados do desafio, uma vez por índice. Confere índice
e compromisso antes de devolver uma share. A ligação XMR ainda verifica a
reconstrução e o ponto público do participante. Esgotar os candidatos retorna
erro explícito com as tentativas; não retorna uma chave incompleta.

O relatório inclui índices tentados/rejeitados, soma dos solves sequenciais e
tempo integral de verificação/busca. Os resultados iniciais abaixo usavam um
novo processo e verificação pública por tentativa. A sessão atual verifica a
oferta uma vez, conserva seus parâmetros e resolve o próximo índice sob demanda.
Cada abertura continua passando em Feldman e o encerramento entra no tempo
integral. Erros de processo/protocolo continuam falhando no cliente
de laboratório; tolerância a interrupções e retomada persistente não estão
implementadas.

Dois testes unitários adicionais cobrem primeira abertura inválida seguida de
reconstrução correta, soma dos custos e esgotamento com escalares inválidos ou
índices trocados. O ensaio financiado usa o backend criptográfico real.

## Resultado medido

[XMR-RECOVERY-BAD-FIRST-REGTEST-RESULT.json](XMR-RECOVERY-BAD-FIRST-REGTEST-RESULT.json):

- Seis puzzles, threshold quatro, três aberturas imediatas; fixture sem
  pretensão de segurança de 128 bits. Uma oferta bastou nesta execução.
- Índices resolvidos: `[1, 2]`; índice rejeitado: `[1]`.
- Preparação/verificação da cápsula: **59,290 s**.
- Mineração inicial de 140 blocos de teste: **31,203 s**.
- Soma dos dois solves sequenciais: **1,317 s**.
- Verificação pública e busca completa: **20,287 s**; com reconstrução,
  **20,293 s**. Medir apenas o solve omite a maior parte desse custo.
- Devolução até inclusão local: **0,281 s**; ambos os outputs gastos depois.
- Total incluindo preparação, mineração e gasto posterior: **122,918 s**.
  Compilação excluída. Nó offline próprio e mineração controlada.

Artefatos: `target/regtest-805102-1790450220133356489/`. Reprodução:

```sh
cargo run --offline --release --locked \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim -j 2 -- /caminho/absoluto/monerod \
  xmr-recovery-bad-first /caminho/absoluto/lhtlp-bridge 6

cargo test --offline --release --locked \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim
```

## Perfil de 198 puzzles

O novo ensaio financiado também passou com 198 puzzles, threshold 100 e 99
aberturas imediatas. Uma oferta bastou nesta execução. A abertura do índice 1
foi rejeitada, a do índice 2 foi aceita e a recuperação permitiu devolução e
gasto de ambos os outputs. Resultado:
[XMR-RECOVERY-BAD-FIRST-198-REGTEST-RESULT.json](XMR-RECOVERY-BAD-FIRST-198-REGTEST-RESULT.json).

- Preparação/verificação: **70,167 s**; mineração inicial: **23,158 s**.
- Solves sequenciais somados: **1,365 s**.
- Verificação pública e busca: **21,755 s**; com reconstrução: **24,522 s**.
- Devolução até inclusão local: **0,307 s**; total: **125,325 s**.
- Artefatos: `target/regtest-808012-1790450933849992856/`.

A execução anterior desse mesmo perfil terminou em timeout após três ofertas
rejeitadas e a aceitação da quarta, antes de concluir o financiamento. Ela não
demonstrou recuperação financiada e permanece registrada em
[XMR-RECOVERY-BAD-FIRST-198-TIMEOUT.json](XMR-RECOVERY-BAD-FIRST-198-TIMEOUT.json).
O guard Tokio de 240 segundos só observou o vencimento quando a preparação
síncrona devolveu o controle; esse valor não é medição exata da duração.
O segundo ensaio é uma execução nova após término confirmado, não retomada
dos mesmos fundos. Não se descartou o resultado desfavorável para afirmar SLA.

Reprodução: usar o mesmo comando acima com `198` no lugar de `6`.

## Sessão com verificação pública única

O ensaio atualizado de 198 puzzles passou: uma oferta rejeitada na preparação,
segunda aceita; índices resolvidos `[1,4]`, rejeição de `[1]`, devolução incluída
e ambos os outputs gastos. A sessão realizou **uma** verificação pública e
encerrou após os dois pedidos. Resultado:
[XMR-RECOVERY-SESSION-198-REGTEST-RESULT.json](XMR-RECOVERY-SESSION-198-REGTEST-RESULT.json).

- Preparação/verificação das duas ofertas: **156,980 s**.
- Mineração inicial: **9,605 s**.
- Verificação pública única: **11,579 s**; soma dos solves: **1,998 s**.
- Sessão completa, incluindo conferências e encerramento: **15,382 s**.
- Recuperação com reconstrução: **18,760 s**.
- Total com gasto posterior: **187,035 s**, acima da meta de três minutos.

Artefatos: `target/regtest-827843-1790452629016971948/`. O
[watchdog externo](XMR-RECOVERY-SESSION-198-WATCHDOG.json) registrou 187,080 s,
exit code 0 e nenhuma interrupção pelo limite de 240 s. Ele iniciou o exemplo
em um grupo de processos próprio e poderia encerrar somente esse grupo.
Compilação excluída. A redução observada da recuperação frente aos 24,522 s
anteriores não é uma comparação controlada entre as mesmas ofertas/carga.

A primeira execução desse cliente expirou na preparação após duas ofertas
rejeitadas, conforme
[XMR-RECOVERY-SESSION-198-TIMEOUT.json](XMR-RECOVERY-SESSION-198-TIMEOUT.json).
Ela não chegou à medição da recuperação. O timeout Tokio só foi observado
após a preparação síncrona devolver o controle; daí o watchdog adicional.

A prova de faixa real também aceitou um puzzle cujo plaintext era `q+1` em
um teste Go separado. A sessão retorna rejeição tipada com seu custo e permite
o próximo candidato. Não normaliza esse inteiro como escalar. O ensaio
financiado acima usa um escalar canônico errado em Feldman; o caso `q+1` foi
exercitado com puzzles reais no teste Go e na busca/reconstrução Rust isolada.
Nove testes Go, três do cliente Rust, dez de prazos, `go vet` e Clippy passaram.

## Preparação do setup antes de divulgar puzzles

O cliente passou a verificar o setup em `prepare-session` antes de liberar
o produtor `open-staged` para criar/divulgar os puzzles. O mesmo processo
público verifica oferta/aberturas, aguarda funding e atende à recuperação.
Assim não repete T quadraturas nem a prova pública depois do depósito.
Os tempos dessas verificações permanecem na preparação e no total.

O ensaio financiado de 198 puzzles passou com essa ordem: primeira oferta
rejeitada antes de funding; segunda aceita; índices `[1,2]`, rejeição de `[1]`,
devolução XMR incluída e ambos os outputs gastos depois. Relatório:
[XMR-RECOVERY-STAGED-198-REGTEST-RESULT.json](XMR-RECOVERY-STAGED-198-REGTEST-RESULT.json).

- Preparação/verificação das duas ofertas: **110,117 s**.
- Mineração inicial: **19,945 s**.
- Setup público da oferta aceita: **0,593 s**, antes dos puzzles.
- Verificação pública de oferta/aberturas: **14,272 s**, antes do funding.
- Dois solves: **1,277 s**; sessão de recuperação: **2,624 s**.
- Recuperação com reconstrução: **5,288 s**.
- Total com gasto posterior: **138,127 s**; compilação excluída.

Artefatos: `target/regtest-831875-1790454223142707007/`.
O [watchdog](XMR-RECOVERY-STAGED-198-WATCHDOG.json) registrou exit 0, sem timeout,
138,173 s e limite externo de 240 s. O tempo está abaixo de três minutos nesse
ensaio isolado, não no protocolo bilateral completo. Não é comparação controlada
de desempenho com as ofertas anteriores. O perfil T=200.000 continua incapaz
de demonstrar margem segura: a oferta é divulgada antes de verificações e
funding, e a abertura observada é muito mais curta que esses intervalos.
Não usar a nova ordem como prova de atraso mínimo ou autorização de depósito.

## Consequência para os prazos

O limite honesto `L_XMR` precisa cobrir as tentativas rejeitadas, a verificação
pública, a reconstrução, o acesso ao material e as interrupções admitidas.
O limite de operações desta busca é o tamanho do conjunto atrasado; ele não
é um limite demonstrado de tempo. Com 198 puzzles há 99 candidatos. O novo
ensaio mede duas tentativas nesse perfil; não mede todos os 99 solves nem
prova segurança de cut-and-choose.

Uma medição bem-sucedida de duas tentativas não estabelece o pior caso nem
o mínimo de tempo de um adversário. A altura DOM conservadora continua
condicionada à âncora ancestral e ao limite do relógio, e só poderá proteger
a composição quando houver uma margem XMR fundamentada. Setup RSA,
preparação autenticada, persistência e corridas completas continuam pendentes.

A [conta exata do orçamento](../recovery-audit/README.md#orçamento-da-busca-após-aceitação)
mostra que a ordem atual deve admitir os 99 candidatos no cenário
Q=2^64/erro 2^-128 para esse componente. `AssumedXmrRecoveryWindow` já deriva
essa contagem do desafio ao calcular a altura DOM condicional, sem converter
o benchmark em garantia. A verificação única já está implementada; considerar
uma busca pública com paralelismo limitado e medir a busca inteira continuam
próximos passos para o custo do mecanismo novo. As premissas criptográficas
continuam necessárias.
