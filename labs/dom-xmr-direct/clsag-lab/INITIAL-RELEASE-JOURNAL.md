# Registro durável da primeira claim

`src/release_journal.rs` acrescenta uma barreira de publicação à primeira
claim do experimento DOM↔XMR. Ela não é o executor completo de recuperação.
Somente os caminhos cooperativos direct-pair usam essa barreira neste momento;
os controles negativos que expõem deliberadamente claims tardias continuam
isolados e não passam por ela.

## Invariante exercitado

Antes de invocar a função de envio, o registro passa de `Private` para
`ExposurePossible` e faz `sync_all`. O prazo é conferido novamente depois da
sincronização: o custo do disco faz parte da janela original. Falha do RPC,
cancelamento da future ou encerramento do processo não restauram `Private`.
Uma retomada nesse estado retorna `NeedsReconciliation`, mesmo antes do prazo.
Isso não prova que os bytes chegaram ao peer; conserva a possibilidade.

Se a primeira tentativa já chega tarde, o registro persiste
`InitialReleaseClosed`. Recuar o relógio e reabrir o mesmo arquivo não permite
iniciar a claim. Esse fechamento só diz respeito à primeira liberação; não
autoriza uma devolução e não extingue um pagamento devido na outra perna.

O cabeçalho vincula a operação, cápsula, timestamp original, limites assumidos,
ordem das pernas, custos de resolução e digest dos bytes exatos da claim.
Reabrir exige a política original. Mudar o timestamp, a ordem ou a operação
produz erro. No ensaio nativo, o vínculo da operação também inclui os corpos
DOM/XMR, a recuperação e a devolução DOM por meio dos bindings existentes.

O arquivo nasce exclusivamente com `create_new`, modo 0600. O arquivo e sua
entrada no diretório são sincronizados. O diretório deve estar previamente
durável e sob controle do operador. O bloqueio exclusivo permanece durante
a vida do handle; outro processo cooperante não consegue abrir um executor
concorrente. O registro usa apenas APIs seguras de `std` e SHA-256 já presente
no laboratório, sem dependência adicional.

A reabertura também sincroniza arquivo e diretório após validar o conteúdo:
o criador anterior pode ter caído entre a gravação do cabeçalho completo e a
sincronização de sua entrada no diretório. Essa etapa não reinicia o prazo.

## Falhas e limites

O leitor limita o tamanho e rejeita cabeçalho ou evento parcial, checksum
incorreto, bytes extras e política divergente. Não descarta automaticamente
uma cauda incompleta, não corrige o arquivo e não cria um substituto quando
`open` falha. Erro durante a gravação inutiliza o handle para novos envios.
O checksum detecta corrupção; não autentica um armazenamento hostil.

Os testes encerram processos sem executar destructors, verificam o bloqueio
entre processos, cancelam uma chamada pendente e corrompem cada byte/cortam
cada posição parcial do arquivo. Uma injeção de descritor sem permissão de
escrita confere que o erro impede a chamada de rede e inutiliza o handle.
Isso cobre essas falhas locais; não simula
queda de energia nem comprova durabilidade de um dispositivo específico.
Remover um evento completo para restaurar um backup antigo não é detectável
por este arquivo sozinho. Exclusão, substituição por symlink, rollback de
backup, escritores que ignoram locks e filesystem que viola fsync estão fora
do modelo de armazenamento confiável. Não há garantia de relógio autenticado.

A função de envio é código confiável: deve transmitir a transação conferida.
A pausa do executor entre a última leitura do relógio e o envio ainda precisa
de um limite; o journal não resolve atrasos arbitrários do processo ou rede.
As premissas de atraso da cápsula continuam sem limites adversariais provados.

Este arquivo não conserva assinatura, segredo, nonce ou share. Ele bloqueia
uma nova liberação automática após exposição possível, mas **não implementa
armazenamento/reabertura segura de sessões de assinatura**, retomada do solver,
disclosure durável antes da oferta, fundos antes da criação do journal,
autenticação entre participantes, reconciliação de cadeias ou tratamento de
reorg. É incorreto declarar a recuperação integral pronta com base nele.
O executor futuro deverá persistir seus materiais e sessões antes de liberar
mensagens, retomar a consulta às cadeias e honrar a contraparte paga, mantendo
a exposição como fato irreversível mesmo se uma inclusão sofrer reorg.

## Verificação

```sh
cargo test --offline --release --locked --test release_journal -j2
cargo build --offline --release --locked --example regtest_claim -j2
target/release/examples/regtest_claim /caminho/monerod \
  direct-pair-xmr-first /caminho/direct-dlog-bridge
```

O teste `crash_child` aparece como ignorado na execução direta porque o teste
principal o lança quatro vezes em processos próprios, com diretórios únicos.
Os modos nativos XMR-first e DOM-first reabrem o registro privado antes do
envio e o registro de exposição depois. Essa reabertura de handle não é uma
reinicialização completa do protocolo. O tempo total inclui essas operações.

Referência das primitivas de arquivo:
[Rust std::fs::File](https://doc.rust-lang.org/std/fs/struct.File.html).

## Evidências desta etapa

`INITIAL-RELEASE-JOURNAL-TESTS.json` registra **32 testes aprovados**: 11 da
barreira durável (um interno e dez de integração), 18 de vínculo/prazos e três
do cliente de recuperação. O helper de processo aparece como ignorado na
listagem principal, mas foi executado pelas quatro chamadas do teste pai.
Clippy de todos os targets também passou com warnings tratados como erro.

`DIRECT-PAIR-DOM-FIRST-JOURNAL-*` concluiu o ensaio nativo em **166,947 s**,
com as duas claims incluídas em **80,649 s**. Inclui o registro durável,
reabertura antes/depois do envio, gasto posterior dos outputs e rejeição da
devolução DOM tardia. Usa a versão que sincroniza também na reabertura.

O ensaio preliminar `DIRECT-PAIR-XMR-FIRST-JOURNAL-*` terminou em **173,535 s**,
com claims em **86,789 s**; seu provenance conserva o binário anterior à
sincronização adicional na reabertura. Houve compilação em paralelo durante
esse ensaio. Ele fica preservado como evidência preliminar, não como execução
da revisão posterior. Cada conjunto mantém seus próprios hashes e watchdog.

A revisão atual de XMR-first, `DIRECT-PAIR-XMR-FIRST-JOURNAL-FINAL-*`, passou
em **166,429 s**, com claims incluídas em **78,718 s**. O registro foi
sincronizado antes do envio e reaberto nos dois estados; os outputs foram
gastos e a devolução DOM foi rejeitada na altura 215. Não houve compilação
concorrente nesta execução. Os hashes de fontes e binários desse conjunto e
de DOM-first conferem com a revisão desta etapa. Esses tempos são ensaios
locais com moedas regtest, não garantia de prazo ou segurança na rede real.
