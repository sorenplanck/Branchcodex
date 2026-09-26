# Auditoria de recuperação temporizada

Este diretório guarda testes e notas de auditoria para primitivas de
recuperação do DXP1. O objetivo é decidir se uma cápsula temporizada pode ser
usada para devolver o próprio ativo da reserva quando a contraparte some.

## VTC primefactor-io

Fonte auditada localmente:

- Repositório: `https://github.com/primefactor-io/vtc`
- Revisão: `b18a1c7153abcff407d6d8469de1f6278fabaa1e`
- Teste: `vtc_fixed_basis_test.go`

O teste deve ser copiado para `pkg/vtc/` da cópia auditada para acessar a
função interna `generateIndexValues`. Ele constrói uma cápsula cujo primeiro
puzzle cifra uma share escalar diferente da share pública correspondente.
Quando o desafio Fiat-Shamir não abre esse índice, a verificação aceita a
cápsula, mas `SolveTimedCommitment` resolve sempre os primeiros `t` puzzles e
recupera uma chave errada.

Resultado observado em 26/09/2026:

```text
vtc_fixed_basis_test.go:131: accepted forged commitment with opened indexes [2 3 5 6 7 8 11 12 14 17]; recovered scalar no longer matches the committed public point
--- PASS: TestAcceptedCommitmentCanRecoverWrongScalar (38.96s)
PASS
ok   github.com/primefactor-io/vtc/pkg/vtc 38.960s
```

Comando usado na cópia auditada:

```sh
env GOTOOLCHAIN=local GOMAXPROCS=2 \
  GOPATH=/home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/clsag-lab/target/recovery-research/gopath \
  GOMODCACHE=/home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/clsag-lab/target/recovery-research/gomodcache \
  GOCACHE=/home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/clsag-lab/target/recovery-research/gocache \
  /home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/clsag-lab/target/recovery-research/go/bin/go \
  test ./pkg/vtc -run TestAcceptedCommitmentCanRecoverWrongScalar -count=1 -v
```

Decisão: esta implementação não deve ser usada como backend direto para a
recuperação DXP1. A cápsula de recuperação precisa verificar a relação entre
cada puzzle recuperável e sua share pública, e a abertura forçada precisa
resolver um conjunto que a verificação aceitou para reconstrução. Uma checagem
final `recovered * G == committed_point` também deve ser obrigatória antes de
autorizar qualquer ação de recuperação.

## Experimento de reparo somente no solver — rejeitado

O teste também tenta usar os `t-1` índices realmente abertos pelo desafio e
cada puzzle restante, verificando o ponto de cada escalar antes de interpolar.
A tentativa inicial falhou: nenhum candidato reconstruiu o ponto comprometido.
O teste registra essa falha como evidência contra esse reparo, sem transformar
o helper em backend. O helper não é um parser seguro para entradas arbitrárias.

A inspeção de `pkg/sss/shares.go` explica o resultado. A implementação escolhe
os primeiros `t-1` escalares livremente e define todos os demais por
`x_j = (secret - sum(L_i * x_i, i < t-1)) / L_j mod q`.
Assim, todos os `L_j * x_j` da cauda repetem a mesma informação. Isso não é
uma avaliação de polinômio Shamir que permita escolher qualquer conjunto de
`t` índices. Os pesos são calculados para o conjunto completo de `n` índices
em `pkg/params/params.go`, não para cada subconjunto de recuperação.

No ataque reproduzido, o puzzle da share zero contém um escalar errado e
essa share não é aberta pelo desafio. Resolver outros puzzles não fornece a
share zero correta; as shares da cauda são redundantes. A verificação final
impede aceitar uma chave errada, mas não devolve a capacidade de recuperação.
Logo, validar após a abertura é necessário e insuficiente para autorizar
financiamento. O novo backend precisa demonstrar recuperabilidade antes disso.

## Custo sequencial local

`TestDelayedPuzzleSequentialCost` gera um puzzle LHTLP real com módulo RSA de
2048 bits, `y=2` e 200.000 quadraturas. Confere a igualdade entre o escalar
original e a abertura. Primeiro resultado local: setup 73,152 ms, geração
69,714 ms e resolução 1,358 s. São medidas de throughput desta implementação
nesta máquina; não são limite inferior adversarial nem garantia de prazo.
A geração de parâmetros conhece os fatores RSA, então esse ensaio também não
prova um setup sem confiança. O ensaio da cápsula adulterada usa dificuldade
1 para estudar correção, não atraso criptográfico.

Execução final conjunta aprovada em 58,417 s: custo sequencial 0,862 s;
reprodução do ataque e rejeição do reparo 57,38 s. Os dez puzzles não abertos
foram tentados; nenhum reconstruiu o ponto por interpolação dos índices.
O helper levou 11,251 s, incluindo nova verificação da cápsula. Esses dez
resultados não são uma prova geral de impossibilidade de recuperação; a
conclusão estrutural acima decorre também da geração das shares inspecionada.

Para executar os dois experimentos, usar o comando acima trocando o filtro por
`-run 'TestAcceptedCommitmentCanRecoverWrongScalar|TestDelayedPuzzleSequentialCost'`.

## Nova composição polinomial com puzzles reais

`polynomial_puzzle_test.go` constrói um polinômio de grau dois e compromissos
Feldman dos seus coeficientes, independentemente do gerador de shares VTC
rejeitado. Cifra seis shares em LHTLP com módulo RSA de 2048 bits e 200.000
quadraturas. Duas shares abertas usam índices fora de um prefixo. O primeiro
puzzle restante contém deliberadamente uma share falsa: a abertura a rejeita
contra o compromisso polinomial e tenta o próximo. A recuperação interpola
os índices reais e confere a chave pública e o segredo esperado.

Resultado local: **aprovado**, total 2,181 s; setup 91,830 ms, cifra das seis
shares 394,886 ms, recuperação com duas aberturas 1,649 s. O teste também
rejeita índices fora do conjunto e adulteração de uma share aberta.

Este experimento usa secp256k1 e não está conectado à recuperação Ed25519 do
crate Rust. O subconjunto aberto é escolhido pela fixture, não por um desafio
criptográfico seguro. Não há prova prévia de que os puzzles restantes cifrem
shares corretas; não há range proof nem verificação de setup hostil nesse novo
ensaio. Os fatores RSA são conhecidos durante a preparação local. Por isso,
o teste demonstra composição algébrica e abertura real, **não** uma cápsula
verificável apta a financiar reservas, segurança temporal ou um swap.

Copiar `vtc_fixed_basis_test.go` e `polynomial_puzzle_test.go` para `pkg/vtc/`
da cópia auditada e usar `-run TestPolynomialRecoveryWithRealDelayedPuzzles` no comando
documentado acima. O novo teste reutiliza somente o helper `containsIndex`
do teste de auditoria; não chama o gerador ou verificador de compromisso VTC.

## Integração local Ed25519/Rust

`lhtlp_bridge.go` é um executável de ensaio separado dos arquivos de testes.
O exemplo Rust `clsag-lab/examples/recovery_puzzle_bridge.rs` cria um segredo
Ed25519 descartável e shares via `RecoveryPlan::from_secret`. Envia apenas
essas shares de teste ao processo Go por stdin. O processo cifra todas e envia
os bytes de setup, puzzles e prova antes de receber os índices do desafio Rust.
Go confere os puzzles abertos usando os nonces originais e resolve um índice
restante. Depois, o Rust chama outra instância do mesmo binário em modo
`verify-openings`; esse verificador recebe somente setup, puzzles, prova,
escalares abertos e nonces, e verifica prova de faixa e aberturas sem acessar
a lista completa de shares secretas. Rust verifica as shares contra Feldman e
reconstrói a chave. Controles negativos rejeitam prova adulterada, nonce errado
e share recuperada adulterada. O relatório público contém somente medidas e
resultados, sem os escalares secretos completos.

O modo `open-only` faz a mesma preparação e abertura seletiva, mas termina sem
resolver nem entregar uma share atrasada. `solve-public` aceita um único objeto
JSON `{ "offer": ..., "index": ... }`: valida o índice e os parâmetros,
recalcula a relação pública de setup, verifica a prova de faixa e só então
resolve o puzzle escolhido. Não recebe fatores RSA ou shares privadas do
emissor. O ensaio Rust `dom_recovery_bridge` executa esse solver depois de o
emissor terminar e de descartar a share original do participante, e usa o
resultado para devolver uma reserva DOM financiada em regtest. A geração do
setup ainda conhece os fatores RSA; separar processos não prova atraso mínimo
nem elimina essa confiança. A chave da reserva completa não é reconstruída.

Ensaio inicial de seis shares, antes da prova de faixa e com índices abertos
2 e 5: setup 0,127 s, cifra 0,386 s, duas aberturas 1,934 s, total
2,460 s, excluindo compilação. RSA de 2048 bits, 200.000 quadraturas por puzzle.
Isso conecta uma abertura real ao módulo Ed25519 de recuperação, mas continua
com setup centralizado descartável, sem prova antes do depósito, autenticação
do processo, garantia temporal adversarial ou transações financiadas. Não é um
serviço de carteira. As cópias de segredos no processo Go/JSON não têm garantia
de apagamento; o exemplo só deve gerar material novo sem valor.

Construir o helper a partir da cópia Go auditada, usando os mesmos caches e
toolchain do comando anterior, substituindo `go test ...` por:

```sh
go build -o ../lhtlp-bridge /home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/recovery-audit/lhtlp_bridge.go
```

Na raiz do clone:

```sh
cargo run --offline --locked --release \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example recovery_puzzle_bridge -j 2 -- \
  /home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/clsag-lab/target/recovery-research/lhtlp-bridge
```

O helper e `lhtlp_bridge_test.go` não devem ser copiados para `pkg/vtc/`: seu
package é `main`. Para testar a fronteira pública usando o mesmo ambiente Go,
executar na cópia auditada:

```sh
go test /home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/recovery-audit/lhtlp_bridge.go \
  /home/leonardov/DOM-XMR-Segundos/labs/dom-xmr-direct/recovery-audit/lhtlp_bridge_test.go -count=1 -v
```

Essa suíte agora tem três testes principais, incluindo 22 casos de entradas
malformadas e a rejeição de um `h` alterado. O parser exige o perfil local
RSA2048, `y=2`, `T=200000`, poderes coerentes do módulo, elementos invertíveis,
160 rodadas completas e respostas limitadas. O verificador recalcula
`h = g^(2^T) mod N` publicamente antes da prova de faixa. O custo dessa
recomputação entra no total do bridge, mas não no campo de tempo da prova.
Isso não prova ausência de fatores conhecidos, que o módulo tenha exatamente
dois fatores apropriados, ordem suficiente dos elementos ou atraso adversarial.
A prova upstream continua com obrigações de auditoria: por exemplo, sua
função `proofDataToHashBytes` concatena inteiros sem framing e não inclui os
parâmetros no próprio desafio. O framing externo do Rust não é uma prova de
segurança desse transcript interno.

O bridge Rust agora também usa `JointPlan::new_with_capsule` para ligar a
assinatura conjunta à cápsula pública verificada e à janela Feldman. Completa
uma CLSAG e extrai o witness. Esse teste usa anel sintético e divide uma chave
descartável gerada centralmente; não é setup distribuído nem input financiado.
Ensaio integrado com as novas verificações aprovado em 68,453 s, incluindo
1,422 s de assinatura conjunta. Relatório completo em
`../clsag-lab/RECOVERY-CAPSULE-JOINT-RESULT.json`; compilação excluída.

A versão atual aceita 6, 132, 166 ou 198 shares pelo segundo argumento do
exemplo Rust (padrão: 198), com threshold `n/2+1`. Gera e verifica uma prova de
faixa upstream com parâmetro de 160 rodadas, e exige rejeição após adulterar
uma resposta dessa prova. Relata separadamente geração, verificação e abertura.
Na versão anterior, a share falsa deliberada passava a prova de faixa porque
ainda era um escalar no intervalo: a prova de faixa não substitui o vínculo Feldman.
Não se atribuem automaticamente 160 bits de segurança a esse parâmetro; a prova
upstream ainda precisa de auditoria. A versão atual substitui a janela par
por índices derivados de `RecoveryChallenge` sobre os bytes reais da cápsula.

Ensaio anterior de janela fixa aprovado com 198 shares e threshold 100: setup 0,084 s, cifra
12,460 s, geração da prova 9,899 s, verificação 10,754 s, duas aberturas 1,955 s,
total 40,943 s. O total inclui comunicação local, checks Ed25519 e controle
negativo da prova; exclui compilação. Relatório exato preservado em
`../clsag-lab/RECOVERY-BRIDGE-RESULT.json`. Não mede o pior caso em que é preciso
tentar todos os puzzles restantes, nem fornece limite inferior contra um
adversário mais rápido. O resultado mede uma instância local do experimento.

## Parâmetros da futura verificação antes do depósito

Integração posterior com desafio real aprovada: 198 puzzles, 99 aberturas
verificadas contra seus nonces no produtor, uma abertura sequencial e
recuperação Ed25519. Um verificador público separado repetiu a verificação da
prova e das 99 aberturas sem receber as shares secretas não abertas. Total:
80,396 s; cifra 12,531 s, geração da prova 10,447 s, verificação da prova no
produtor 10,901 s, verificação das aberturas no produtor 6,086 s, resolução
1,009 s, verificação pública externa da prova 10,889 s e das aberturas 6,444 s.
Compilação excluída. Resultado exato em
`../clsag-lab/RECOVERY-CHALLENGE-BRIDGE-RESULT.json`.
Os bytes do transcript são strings JSON produzidas pelo serializador Go local;
não constituem ainda um formato de rede interoperável e auditado. A geração
descartável ainda conhece todos os segredos. O verificador público não prova
setup sem confiança, resistência a cápsulas hostis fora do parser local,
recuperação após restart ou vínculo à transação da rota.

Fonte primária consultada: apêndice E, figura 16 e teorema 9 de
[Verifiable Timed Signatures Made Practical](https://verifiable-timed-signatures.github.io/web/assets/paper.pdf).
O argumento de soundness usa um desafio uniforme que abre metade dos puzzles:
sem uma share correta entre os restantes, o emissor precisa adivinhar exatamente
o subconjunto aberto. A fonte também exige correção dos puzzles e prova de faixa.
Isso não torna a implementação auditada equivalente ao argumento do artigo.

O cálculo próprio em `cut_choose_budget.py` aplica o limite conservador
`min(1, Q / binomial(n, n/2))`, onde Q é o número de tentativas do adversário.
Ele pressupõe um transcript imutável e desafio uniforme, compromissos
polinomiais válidos e provas de setup/faixa corretas. Não mede os erros dessas
outras provas, segurança RSA, vazamento de shares ou resistência temporal.

Parâmetros mínimos calculados com inteiros exatos para esse componente ter
limite de falha <= 2^-128:

| Tentativas Q | Puzzles n | Shares abertas | Threshold |
| --- | ---: | ---: | ---: |
| 1 | 132 | 66 | 67 |
| 2^32 | 166 | 83 | 84 |
| 2^64 | 198 | 99 | 100 |

Esses orçamentos são cenários explícitos, não estimativas aprovadas do poder
adversarial. Com seis puzzles e abertura de três, o limite de uma tentativa é
1/20; com vinte e abertura de dez é 1/184756. Os ensaios anteriores não
implementam esse desafio e não herdam nem mesmo esses limites. Em particular,
a fixture Ed25519 anterior abre duas de seis, e não três de seis.

Cinco testes aprovados verificam a fórmula por enumeração exaustiva até oito
puzzles, minimalidade dos parâmetros, união de tentativas e entradas inválidas.
Consequência: o próximo protótipo pré-verificável deve medir geração e prova
com parâmetros explícitos maiores, e não extrapolar a segurança ou o tempo dos
ensaios de seis shares. Ainda faltam o desafio vinculado à rota e aos parâmetros,
range proof auditada, validação de setup e limites de custo para cápsulas hostis.

```sh
python3 -B labs/dom-xmr-direct/recovery-audit/cut_choose_budget.py
python3 -B -m unittest discover -s labs/dom-xmr-direct/recovery-audit -p 'test_*.py' -v
```

## Orçamento da busca após aceitação

O resultado de cut-and-choose acima exige poder tentar todo o conjunto
atrasado. Ele não autoriza limitar a recuperação à primeira share, nem às duas
shares do ensaio financiado com primeiro puzzle inválido.

Para o cliente atual, que visita os índices atrasados em ordem crescente,
o evento de uma oferta **ser aceita e ainda não fornecer share válida após k
solves** tem limite, em Q tentativas de transcript:

```
min(1, Q * binomial(n-k, n/2) / binomial(n, n/2))
```

Derivação: uma oferta fixa com b puzzles incompatíveis só é aceita se a metade
aberta evitar todos eles. Para frustrar k solves é necessário b >= k. A
probabilidade de evitar b posições é `binomial(n-b,n/2)/binomial(n,n/2)`,
máxima em b=k. Colocar esses k puzzles nos primeiros índices atinge o limite
porque, quando a oferta é aceita, todos eles estarão no início da busca.
Para Q transcripts usa-se a união dos eventos, sem supor independência.
Não é uma probabilidade condicionada à aceitação, nem inclui falhas das outras
provas ou de disponibilidade.

Com n=198, uma única tentativa de transcript já aceita o caso de primeiro
puzzle inválido com probabilidade 1/2; para dois primeiros inválidos, 49/197.
No cenário Q=2^64 e alvo <=2^-128 para esse componente, k=98 ainda não basta;
**k=99 é necessário neste limite e nesta ordem de busca**. Isso não estabelece
128 bits de segurança do protocolo ou do backend.

`accepted_search_failure_bound` e `minimum_search_budget`, em
`cut_choose_budget.py`, fazem as contas com frações exatas. Cinco testes novos
enumeram todos os conjuntos abertos e todas as posições adulteradas até n=8,
conferem a fórmula, a minimalidade e a coincidência com o limite anterior
quando toda a busca é permitida. A suíte de orçamento tem dez testes aprovados.
Resultado: [SEARCH-BUDGET-RESULT.json](SEARCH-BUDGET-RESULT.json).

Consequência temporal: contabilizar o pior orçamento de busca na margem DOM,
sem usar o número de tentativas observado em uma execução favorável. O cliente
serial anterior revalidava a prova pública inteira em cada candidato. A sessão
descrita abaixo elimina essa repetição, mantendo a verificação do compromisso
de cada share; não se pode simplesmente retirar tentativas do prazo.

## Sessão pública com verificação única

O cliente Rust dos ensaios financiados agora usa a preparação em duas fases:
`open-staged` anuncia somente o setup e espera seu SHA-256 reconhecido;
`prepare-session` verifica a relação sequencial antes de emitir `setup_ready`.
Somente então o produtor honesto cria e divulga puzzles/prova. O verificador
retido exige os mesmos bytes de setup, valida prova e partição de aberturas,
e passa a atender os pedidos de solve. O Rust confere desafio/Feldman antes
de devolver a cápsula para funding. Os modos anteriores permanecem controles.

Três testes Go adicionais comprovam a ordem usando pipes sem puzzles na
primeira fase; rejeitam substituição de setup, prova/abertura falsa, conjuntos
sobrepostos, oferta prematura e setup inconsistente. Os 12 testes passaram
em 48,503 s; `go vet` passou. A divulgação não é reiniciada por essa mudança.
O processo público começa antes do produtor encerrar; o trabalho de solve
continua ocorrendo depois que o produtor terminou. Não há autenticação de
rede, persistência/restart ou prova de atraso mínimo nessa separação local.

O modo `solve-session` recebe somente uma oferta pública e a lista ordenada
de índices atrasados. Faz parsing limitado, verifica a relação de setup e a
prova de faixa e conserva uma cópia interna dos parâmetros/puzzles. Só depois
emite `ready`. Cada pedido subsequente deve ser o próximo índice dessa lista.
Outra oferta, índice repetido, ordem diferente, excesso de pedidos, mensagens
sem newline, linhas vazias e valores JSON adicionais são rejeitados.

A busca continua sequencial, sob demanda. Encerrar stdin para a busca antes
dos demais candidatos: a resposta final informa quantos foram resolvidos e
o cliente confere esse número e o término bem-sucedido. Não há trabalho
especulativo escondido após o resultado. O Rust confere a lista contra o desafio
exato e verifica cada abertura em Feldman. O modo `solve-public` permanece
como controle independente de uma tentativa.

Os nove testes Go incluem snapshot imutável, ausência de `ready` para prova
inválida, segunda abertura na mesma sessão, encerramento antecipado sem resolver
o próximo índice, substituições e framing, além das verificações anteriores.
Fixtures Go de grupo identidade/zero isolam essas fronteiras; o ensaio Rust
financiado usa puzzles e escalares aleatórios reais. Setup RSA, atraso mínimo,
prova de faixa upstream e persistência continuam obrigações separadas.

### A prova de faixa não assegura um escalar canônico

`TestAcceptedRangeProofCanContainNoncanonicalPlaintext` gerou seis puzzles
reais, um contendo `q+1`, e uma prova de faixa de 160 rodadas que passou no
verificador público. A abertura desse puzzle foi rejeitada pelo decoder de
escalares; outro puzzle permaneceu recuperável. Portanto, uma falha desse
decoder não pode encerrar toda a busca por uma share válida.

A sessão agora devolve `invalid/noncanonical_plaintext` com índice e tempo
gasto, conserva o estado verificado e aceita o próximo índice autorizado.
Não reduz o inteiro módulo q nem o aceita como share. O teste real verifica
rejeição do índice 1, resolução do índice 3 e encerramento com dois candidatos
processados. O cliente Rust também testa continuação, esgotamento e soma de
custos para essas rejeições. Essa cobertura é de recuperação/parsing; não é
uma auditoria completa da prova de faixa ou da dureza temporal.

## Custo de processar os 99 candidatos

A investigação seguinte usa uma prova de relação direta entre um puzzle e
o ponto Ed25519, para tentar evitar a busca de até 99 aberturas. O modelo
algébrico e o primeiro experimento real passaram; estado, parâmetros, tempos,
limites e reprodução em
[DIRECT-PLAINTEXT-RESEARCH.md](DIRECT-PLAINTEXT-RESEARCH.md). Essa construção
é experimental, não substitui o backend financiado e não está autorizada pela
mera passagem desses testes. A rejeição antiga de `q+1` permanece inalterada.

`lhtlp_full_search_test.go` força 98 plaintexts não canônicos `q+1` e uma
abertura válida no último candidato. A partição ímpar/par é fixa: o teste
não deriva Fiat-Shamir nem fabrica a alegação de aceitação de uma cápsula
real. Essa fixture mede o volume de trabalho difícil de obter por amostragem.
Usa puzzles reais, prova de faixa real, setup verificado antes da geração,
99 aberturas imediatas conferidas e o mesmo laço público de busca ordenada.

Reprodução no módulo Go local já preparado, com os caminhos dos dois arquivos:

```sh
go test /caminho/lhtlp_bridge.go /caminho/lhtlp_full_search_test.go \
  -run '^$' -bench '^BenchmarkPreparedSearch198$' -benchtime=1x -timeout 5m -v
```

Resultado aprovado: preparação 35,862 s; busca completa **64,716 s**; total
100,578 s, com T=200.000. Todas as 98 rejeições foram conferidas; o último
escalar coincidiu com o esperado e o encerramento registrou 99 resoluções.
Relatório: [FULL-SEARCH-WORKLOAD-RESULT.json](FULL-SEARCH-WORKLOAD-RESULT.json).
`go vet` passou. O tempo não inclui Feldman/Rust, IPC, financiamento ou
reconstrução; não é limite de pior caso nem atraso mínimo adversarial.

Essa medição mostra o custo que faltava nas duas tentativas do regtest.
Aumentar a dificuldade de todos os puzzles mantém o custo de até 99 solves.
Ainda é necessário estabelecer uma janela útil após a oferta e avaliar uma
construção que reduza esse trabalho sem enfraquecer o vínculo ao ponto público.
