# Decisão durável antes de trocar adaptors

O journal da primeira claim só existia depois da preparação dos adaptors.
Sua ausência não provava que uma operação ainda estava privada. O worker de
devolução agora exige uma decisão anterior, criada antes dos dois depósitos:
`preparation.wal`, ligada à cápsula/roster original e ao recebimento original.

## Decisão única

`PreparationGate` começa em `Private`. Sob lock exclusivo e após fsync pode
avançar para exatamente um dos estados:

- `ExchangePossible { operation }`, ANTES de entrar no código de troca de
  adaptors. Guarda o digest final que vincula as duas claims. Erro, cancelamento
  ou queda antes do envio não devolve privacidade.
- `RecoveryOnly { job }`, que reserva a operação ao job exato de recuperação
  anterior à entrega de adaptors. O mesmo job pode reabrir o estado; outro job
  ou uma tentativa posterior de iniciar a troca são recusados.

Não há transição entre esses dois estados nem volta para Private. Arquivos
ausentes, parciais, públicos, symlinks ou identidade diferente falham sem reparo
automático. Arquivo 0600/create_new/fsync; root dos modos direct-pair é 0700,
com diretório e entrada no pai sincronizados antes. Um erro na escrita invalida
o handle em memória. Header/evento têm checksum e leitura limitada.

Isso depende de storage local confiável, escritores respeitando o lock e fsync
honesto. Remover um evento COMPLETO por rollback de backup não é detectado;
os testes não apresentam essa ameaça como corrupção parcial resolvida.
O registro não autentica peer, cadeia, relógio nem segurança da cápsula.

## Integração

Todos os modos direct-pair criam a barreira após aceitar a cápsula e antes de
financiar as reservas. O caminho cooperativo marca ExchangePossible antes de
`dom.offer` e `presign`. `journaled_initial_send` exige a mesma operação nessa
barreira antes de usar o InitialClaimJournal original. O worker de settlement
também exige esse estado ligado ao manifest antes de observar/republicar claims.
A decisão não substitui a janela inicial ou a obrigação da contraparte devida.

O worker de devolução abre a barreira e reserva o job ANTES de carregar shares
ou iniciar o solver; mantém o lock durante recuperação/assinatura. O pai
confere RecoveryOnly e testa a recusa de iniciar troca depois da conclusão.
Esse custo entra nos mesmos 65 segundos assumidos. As variantes antigas de
abandono só no pai também registram uma finalidade de recuperação ligada à
cápsula; continuam sem o job de assinatura durável completo do worker novo.

Os cenários de disputa DEPOIS da entrega continuam separados: não recebem
autorização de Private nem podem usar este worker como atalho. Ausência de
initial-claim.wal jamais é evidência suficiente de não exposição.

## Cobertura e limites

Passaram 32 testes Rust (cinco da barreira, 11 do journal inicial, 16 do
exemplo), Clippy all-targets -D warnings e build, em
`PREPARATION-GATE-CHECKS.json`. Helpers ignorados na listagem são executados
pelos testes pais em processos novos: quedas sem destructors depois da escolha,
lock entre processos e rejeição do caminho oposto após reabertura.
Também cobrem troca de operação/job/cápsula/recebimento, corrupção de cada byte,
cortes parciais, extensão, permissions e symlink. Um teste do worker comprova
recusa de operação exposta antes de procurar as shares ou iniciar o Go.

A barreira é um requisito para publicação independente, não sua implementação.
O supervisor ainda publica a devolução e hospeda os nós. Persistência/reconciliação
do envio de refund, recuperação após exposição, número global de quedas,
preparação independente, fundamentação de segurança e dom-interopd seguem
pendentes. O mesmo job reabrir não significa orçamento ilimitado de tentativas.

## Recuperação nativa

PID1418559, exit0: **174,093 s** totais / **43,715 s** de recuperação integral,
incluindo a decisão durável e a conferência pelo pai. Recebimento1790482735,
início1790482770 (+35), XMR refund observado1790482813 antes do limite1790482835.
DOM lock219/refund220/gasto221. Outputs de ambas devoluções gastos.
O registro final tem RecoveryOnly com o digest exato do job; tentativa de
iniciar troca depois da recuperação foi recusada. Não renovou o recebimento.

PIDs pai1418559/Rust1441087/Goantigo1418622/novo1441093 e grupo ausentes;
hashes de fontes/binários conferidos, session86935 terminou. Artefatos
`DIRECT-PAIR-ABANDON-PREPARATION-GATE-*`. Passou nos limites observados de
65 s de recuperação e 180 s totais; sem prova de garantia temporal.

## Troca e retomada cooperativa nativas

`direct-pair-xmr-first-native-replay`, PID1462686, exit0: **178,899 s** totais
(parede178,924 s), claims incluídas em **84,314 s**. Worker1463064 republicou
a primeira XMR e encerrou com exit79 depois do ACK; outro processo observou
pool e reinclusão152→153, preservando os registros/janelas. A contraparte foi
publicada por worker; outputs gastos e refund DOM conflitante recusado em221.

O arquivo final contém ExchangePossible e a MESMA operação do manifest
original. A tentativa de adquirir RecoveryOnly após essa decisão foi recusada
antes dos adaptors. As chamadas de retomada exigiram essa autorização além do
journal de exposição inicial e das observações nativas existentes.
Leituras DOM públicas/autenticadas86/28, um POST, zero429; não dizer que o
backoff foi exercitado nesta execução. Controle pool/inclusão/estado incerto
suprimiu os envios previstos. Prefixo
`DIRECT-PAIR-XMR-FIRST-REPLAY-PREPARATION-GATE-*`.

Hashes conferidos, pai/workers/grupo encerrados, session68082 terminou.
`PREPARATION-GATE-VERIFICATION.json` resume as duas execuções. Nenhum ensaio
pendente. A margem total deste cenário é pequena; resultados anteriores mais
lentos continuam válidos e não são substituídos por uma garantia de prazo.
