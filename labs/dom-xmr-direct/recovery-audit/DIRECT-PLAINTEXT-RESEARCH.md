# Vínculo direto entre puzzle e ponto público — investigação

Estado: modelo algébrico e experimento Go com puzzle real implementados;
**sem implementação aprovada para funding**. Não substitui o cliente de
recuperação existente. A missão continua DOM↔XMR.

## Motivo concreto

O benchmark integral processou 99 candidatos em 64,716 s com T=200.000;
98 foram rejeitados e o último abriu corretamente. É uma fixture de partição
fixa, não uma cápsula aceita por Fiat-Shamir. O regtest com duas aberturas levou
138,127 s totais, mas a verificação da oferta aceita levou 14,272 s e os solves
somaram 1,277 s. Não existe margem adversarial demonstrada nesse perfil.
Aumentar o atraso individual também multiplica o trabalho serial por até 99.

A hipótese a testar é provar antes do funding que **um** ciphertext contém
um inteiro correspondente ao ponto Ed25519 esperado. Isso permitiria procurar
uma construção com uma abertura, mantendo a verificação posterior do ponto.
O resultado pretendido ainda exige correção, soundness, privacidade e tempo;
apenas trocar a estrutura de dados não satisfaz essas obrigações.

## Referências primárias consultadas em 26/09/2026

- [Verifiable Timed Signatures Made Practical](https://eprint.iacr.org/2020/1563)
  usa cut-and-choose e provas de faixa. É a direção de referência já auditada
  neste laboratório, não demonstra que basta resolver o primeiro candidato.
- [Efficient CCA Timed Commitments in Class Groups](https://eprint.iacr.org/2021/1272)
  propõe setup transparente e trabalho sequencial essencialmente independente
  do número de participantes. É outra família; não fornece automaticamente
  a ligação Ed25519 nem compatibilidade com o helper RSA atual. A variante
  heurística do artigo precisa ser distinguida da construção demonstrada.
- [paillier-zk 0.4.3, Πlog*](https://docs.rs/paillier-zk/0.4.3/src/paillier_zk/group_element_vs_paillier_encryption_in_range.rs.html)
  implementa uma prova de relação entre plaintext Paillier, ponto de curva e
  faixa. A relação do nosso puzzle tem também `U=g^r`; importar somente uma
  prova Paillier sem ligar esse componente não resolve recuperabilidade.
- [Direct Range Proofs for Paillier Cryptosystem and Their Applications](https://eprint.iacr.org/2024/1355)
  é referência para provas com respostas inteiras e limites explícitos. Exige
  leitura/instanciação da relação exata antes de alegar aplicação ao puzzle.
- [Auditoria de falhas em provas especializadas, Trail of Bits](https://blog.trailofbits.com/2022/11/29/specialized-zero-knowledge-proof-failures/)
  reproduz falsificações por falta de validação de elementos de grupo em
  provas de log e plaintext. Os testes novos precisam rejeitar zero, elementos
  não invertíveis, pontos inválidos e respostas fora do domínio.

## Relação local a investigar, não uma prova de segurança pronta

No helper fixado, Y=2 e:

```
U = g^r mod N
V = h^(r*N) * (1+N)^m mod N²
h = g^(2^T) mod N
P = (m mod q) * G
```

Uma hipótese de protocolo Sigma repete desafios de um bit. Cada compromisso
inclui um puzzle de máscaras `(a,b)` e o ponto `aG`; respostas inteiras seriam
`z_m=a+c*m`, `z_r=b+c*r`. A verificação conjunta deve usar o mesmo bit em
**ambos** os componentes do puzzle e no ponto de curva. Hashes precisam
vincular parâmetros, dificuldade, domínio, rede, papel, contexto, ponto,
ciphertext, todos os compromissos e limites com codificação inequívoca.

Essa hipótese precisa de limites inteiros e análise de extração; uma igualdade
somente módulo q não assegura que o inteiro aberto seja o mesmo que o ponto.
Sem faixa, soluções por congruências diferentes podem invalidar a relação
pretendida. Se a extração permitir um representante assinado, sua magnitude
precisa ser estritamente menor que N/2, com decodificação única e prova da
correspondência ao ponto. **Não alterar a rejeição de q+1 no backend atual.**
Uma redução módulo q só poderia existir num backend separado cuja prova
estabelecesse explicitamente essa relação; o range proof atual não o faz.

## Próximo experimento e critérios de rejeição

1. Modelar a álgebra em parâmetros pequenos e enumerar falhas de binding,
   respostas sem limite, representantes negativos e wraparound módulo N/q.
2. Especificar distribuição de máscaras, limites das respostas e extração de
   dois transcripts com mesmo compromisso/desafios opostos. Não reduzir
   respostas inteiras módulo q antes das equações do puzzle.
3. Só depois implementar uma prova experimental Ed25519/puzzle isolada:
   segredo correto, ponto/ciphertext errados, outro setup/contexto, torsão,
   elementos não invertíveis, framing e respostas fora da faixa.
4. Medir geração/verificação e uma abertura, incluindo todos os custos;
   manter a divulgação original, prova pública antes de funding e checagem
   final do ponto. Derivar o orçamento de Fiat-Shamir/grinding separadamente.
5. Auditar privacidade, setup/trapdoor, mínimo adversarial e máximo honesto.
   Testes algébricos não constituem essas provas nem autorização de depósito.

## Evidência algébrica obtida

`direct_plaintext_model.py` usa N=77 e o grupo aditivo de ordem 5 como
substituto algébrico da curva. Enumera 1.155 statements e confere 7.488 pares
de respostas aceitos, cobrindo todo o retângulo de respostas configurado.
Nenhum desses pares abriu para outro ponto. O resultado está em
[DIRECT-PLAINTEXT-MODEL-RESULT.json](DIRECT-PLAINTEXT-MODEL-RESULT.json).

Oito testes passaram. Dois controles negativos **conseguem falsificar** a
relação sem limites adequados: retirar o limite de resposta permite somar
múltiplos de N ao plaintext e mudar o ponto; permitir magnitude >=N/2 torna
a representação assinada ambígua. Outros casos cobrem extração negativa,
componentes U/V, não unidades, mudança de compromisso e bordas de decoding.
Essa enumeração finita não prova soundness geral, zero knowledge ou atraso.

## Candidato real e argumento de extração a auditar

`direct_dlog.go` implementa 256 rodadas de um bit, com máscaras inteiras de
256 bits de folga estatística. Usa o envelope de parâmetros já verificado
do laboratório; o campo legado RangeBits=160 desse envelope não determina
as 256 rodadas da prova direta. O domínio próprio inclui versão/rodadas/folga,
e o hash com framing inclui setup exato, contexto, ordem/gerador, ponto,
ciphertext e todos os compromissos. O verificador exige contexto e chave
esperados do chamador, e não os aceita só porque vieram na oferta.

Para q de Ed25519, as máscaras são escolhidas em `[0,B_m)` e `[0,B_r)`:

```
B_m = 2^(bitlen(q)+256)
B_r = N² * 2^256
0 <= z_m < L_m = B_m + q
0 <= z_r < L_r = B_r + N²
2*L_m < N
```

O argumento algébrico que motiva a proposta é: dois transcripts aceitos para
o mesmo compromisso com bits 0 e 1 dão `d_m=z_m1-z_m0` e `d_r=z_r1-z_r0`.
Subtraindo as equações resulta `Enc(d_m,d_r)=C` e `d_m*G=P`. A relação
de setup `h=g^(2^T) mod N` e a identidade `(x+kN)^N=x^N mod N²` implicam que
a abertura de C retorna `d_m mod N`. Como `|d_m|<L_m<N/2`, o representante
assinado é único; somente depois dessa decodificação e da checagem do ponto
se converte para o escalar módulo q. Isso explica a necessidade das bordas
do modelo; não substitui a auditoria do protocolo, Fiat-Shamir ou privacidade.

O argumento de extração requer todas as equações e respostas inteiras. O
código valida unidades, pontos canônicos e pertença ao subgrupo primo
(inclusive rejeição de pontos com torsão somada a um ponto válido). O ponto
público identidade é rejeitado; compromissos de máscara identidade são
permitidos. O objeto aprovado conserva uma cópia do puzzle e do ponto.
O decoder antigo continua rejeitando `q+1`: a redução nova pertence somente
ao tipo privado que recebeu a prova direta.

## Primeiro ensaio real

Quatro testes Go passaram, incluindo 19 mutações adversariais: contexto,
chave, setup, componentes de ciphertext, torsão, ausência/excesso de dados,
respostas negativas/fora da faixa e alterações das respostas. Também
verificaram isolamento do snapshot e rejeição de replay para outro contexto.
O helper usa `filippo.io/edwards25519 v1.1.0` (BSD-3-Clause), fixado apenas no
módulo Go de pesquisa. Checksum de módulo:
`h1:FNf4tywRC1HmFuKW5xopWpigGjJKiJSV0Cqo0cJWDaA=`.
O [código primário](https://raw.githubusercontent.com/FiloSottile/edwards25519/v1.1.0/edwards25519.go)
explica que SetBytes permite formas não canônicas; o experimento exige
igualdade com a recodificação canônica e confere `[q]P=identidade`.

Resultado [DIRECT-DLOG-RESULT.json](DIRECT-DLOG-RESULT.json), T=200.000:

- Setup e sua verificação: 0,835 s.
- Geração da prova: 17,433 s.
- Verificação da prova: 17,236 s.
- Abertura única e checagem do ponto: 0,740 s.
- Total do caminho positivo: 36,248 s; JSON público 901.937 bytes.

O teste completo, incluindo controles negativos, levou 37,163 s; `go vet`
passou. Não inclui IPC, funding, claims, espera nativa ou compilação. O perfil
tem abertura observada muito mais curta que a verificação pública e não
oferece uma margem temporal demonstrada para proteger a troca.
O helper continua com RSA de 2048 bits e não demonstra segurança global de
128 bits; 256 rodadas/folga não são uma alegação sobre o sistema completo.

Reprodução no módulo Go de pesquisa já preparado:

```sh
go get filippo.io/edwards25519@v1.1.0
go test /caminho/lhtlp_bridge.go /caminho/direct_dlog.go \
  /caminho/direct_dlog_test.go -run '^TestDirect' -count=1 -timeout 5m -v
python3 -m unittest -v test_direct_plaintext_model.py
```

## Integração com processos e roster Rust

O helper opcional `direct_dlog_cli.go` acrescenta `direct-produce` e
`direct-prepare` somente ao build que inclui esse arquivo e `direct_dlog.go`.
O executável anterior continua compilável apenas com `lhtlp_bridge.go`.
Há setup reconhecido antes da oferta, frames limitados, binding dos bytes
exatos do corpo público e um único pedido de abertura. Cancelamento por EOF
não inicia solve; pedido repetido, outro binding e frame incompleto falham.

`examples/direct_recovery_bridge.rs` cria shares aditivas originais, entrega
somente uma ao produtor, confere o ponto Go contra o ponto Ed25519 Rust e
mantém o verificador público sem essa share. O produtor termina antes da
abertura. O cliente compara hashes dos mesmos bytes e só aceita a abertura
depois de verificar ponto, escalar canônico, contador e término do processo.
`XmrDirectRecoveryLink` confere contexto/chave contra roster/papel antes de
criar o vínculo e confere novamente roster/papel/binding na recuperação.
Chaves já ajustadas pelo offset ou escaladas são recusadas na preparação.

O primeiro ensaio entre processos passou em **42,014 s**, sem financiamento,
restaurando a share individual e aplicando o offset somente depois. Resultados
`clsag-lab/DIRECT-DLOG-IPC-INITIAL-*`; compilação excluída e watchdog externo
de 120 s sem timeout. Esse ensaio já conferia contexto/chave no bridge; a
revisão seguinte tornou essa conferência obrigatória também no construtor
Rust, antes de qualquer abertura. Não se mediu latência de rede principal.

Após essa revisão, o ensaio repetido passou em **37,838 s**: setup público
1,016 s; geração 17,940 s; verificação 17,517 s; abertura 1,119 s. O processo
público terminou corretamente, com uma abertura. Resultado
[DIRECT-DLOG-IPC-RESULT.json](../clsag-lab/DIRECT-DLOG-IPC-RESULT.json) e
[watchdog](../clsag-lab/DIRECT-DLOG-IPC-WATCHDOG.json), sem timeout. O intervalo
desde receber a oferta até pedir a abertura foi 17,537 s, o que mantém evidente
a falta de margem do perfil curto. A diferença entre execuções não constitui
comparação controlada de velocidade.

Vinte testes Go distintos passaram nesta etapa (12 anteriores, quatro de
prova direta e quatro de mensagens), com 25 testes Rust (21 de assinatura/
recuperação existentes e quatro do novo vínculo). Clippy de todos os targets
e `go vet` passaram. O argumento interno e suas limitações estão em
[DIRECT-DLOG-AUDIT.md](DIRECT-DLOG-AUDIT.md).

Reprodução com o mesmo módulo Go e dependências fixadas:

```sh
go build -o /caminho/direct-dlog-bridge /caminho/lhtlp_bridge.go \
  /caminho/direct_dlog.go /caminho/direct_dlog_cli.go
cargo build --offline --release --locked --example direct_recovery_bridge -j 2
target/release/examples/direct_recovery_bridge /caminho/absoluto/direct-dlog-bridge
```

## Devolução nativa XMR com a cápsula direta

`regtest_claim ... xmr-direct-recovery` verificou a cápsula antes de financiar
a reserva local, descartou a share original do peer, abriu a cápsula em outro
processo e restaurou a share original no Rust. O ponto e binding foram
conferidos, uma share falsa foi rejeitada, e o offset veio depois. A transação
CLSAG de devolução foi incluída pelo monerod; ambos os outputs foram gastos.

O total foi **52,027 s**, incluindo 30,667 s de preparação da cápsula,
18,794 s de preparação dos fundos e 0,673 s de recuperação com conferência.
Relatório [XMR-DIRECT-RECOVERY-REGTEST-RESULT.json](../clsag-lab/XMR-DIRECT-RECOVERY-REGTEST-RESULT.json)
e [watchdog](../clsag-lab/XMR-DIRECT-RECOVERY-WATCHDOG.json). Compilação excluída,
mineração local controlada, sem teste de mainnet. O intervalo após receber a
oferta foi 33,689 s, contra abertura de 0,671 s: falta margem de segurança.

`AssumedXmrRecoveryWindow::from_direct_costs` agora liga uma abertura ao vínculo
exato da cápsula/roster/papel. Conserva o instante original de divulgação e a
altura DOM conservadora; a conta anterior continua com 99 candidatos. São
12 testes de prazos, quatro do vínculo direto e três do cliente aprovados
nesta etapa; Clippy de todos os targets passou. As premissas hipotéticas dos
testes não foram usadas como permissão de depósito: o ensaio financiado
registra `timing_admission_used=false` e `safe_bilateral_window_proven=false`.

Reprodução, com o bridge construído como acima:

```sh
cargo build --offline --release --locked --example regtest_claim -j 2
target/release/examples/regtest_claim /caminho/absoluto/monerod \
  xmr-direct-recovery /caminho/absoluto/direct-dlog-bridge
```

O perfil T=10.000.000 foi medido no mesmo caminho de financiamento por
coinbase: **130,227 s** totais, setup 31,658 s, geração 14,852 s, verificação
14,982 s, abertura 39,536 s. A espera após receber a oferta foi 40,376 s,
portanto aumentar T sozinho não resolveu a janela. Relatório
[XMR-DIRECT-RECOVERY-10M-REGTEST-RESULT.json](../clsag-lab/XMR-DIRECT-RECOVERY-10M-REGTEST-RESULT.json)
e [watchdog](../clsag-lab/XMR-DIRECT-RECOVERY-10M-WATCHDOG.json), sem timeout.
O argumento final `10000000` seleciona esse perfil; ambos os processos recebem
e conferem a escolha. Valores fora da lista, downgrade e h inconsistente são
rejeitados; o backend anterior continua fixo em T=200.000. Nenhum perfil é
uma política aprovada de segurança temporal.

## Depósito nativo separado da preparação do saldo

O ensaio seguinte gerou o saldo numa carteira individual antes de divulgar a
cápsula. Somente depois de verificar a oferta, assinou e publicou uma
transferência nativa de 5 XMR de teste para a reserva compartilhada. Conferiu
inclusão e valor, gerou os dez blocos de maturação locais e então recuperou a
share. Devolução e gasto dos dois outputs passaram. A preparação do saldo
continua no total: não se introduziu uma reserva compartilhada antecipada.

Com T=10.000.000: saldo 14,157 s, preparação da cápsula 66,445 s, depósito e
maturação 1,009 s, recuperação 48,180 s, **total 131,917 s**. O tempo entre
receber a oferta e iniciar a abertura foi **17,423 s**, contra **48,179 s**
da abertura. Relatório
[XMR-DIRECT-TRANSFER-10M-REGTEST-RESULT.json](../clsag-lab/XMR-DIRECT-TRANSFER-10M-REGTEST-RESULT.json)
e [watchdog](../clsag-lab/XMR-DIRECT-TRANSFER-10M-WATCHDOG.json), sem timeout.
O mesmo comando com argumento final `10000000` reproduz esse caminho atual.

A diferença positiva é local. Não é `E_XMR`, não delimita hardware adversarial
e não fornece máximo honesto. A variação da abertura entre execuções já impede
tratar um benchmark isolado como limite. A maturação foi minerada sob demanda
na fakechain; não é uma medição da espera na rede principal. O relatório
continua com admissão temporal e segurança bilateral não comprovadas.

Próximo: estabelecer uma margem útil sob premissas verificáveis e compor
devolução e claims concorrentes. Ainda faltam auditoria criptográfica,
autenticação e persistência; esses testes não autorizam depósitos reais ou
uma alegação de swap seguro.

Se essa direção falhar, o candidato atual não ganha uma exceção ao orçamento
de 99. A comparação com class groups ou outras provas precisará preservar
as mesmas obrigações e as medições completas.
