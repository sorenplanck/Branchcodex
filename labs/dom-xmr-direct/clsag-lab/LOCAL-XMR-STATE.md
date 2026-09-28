# Estado local de recuperação XMR

`xmr_recovery::checkpoint::LocalXmrRecoveryCheckpoint` persiste a share local
original, o identificador da reserva, as duas chaves públicas ordenadas, o
papel local, o binding exato da cápsula, seu recebimento original e dificuldade.
Não serializa chave agregada, offsets de output, nonces ou sessões de assinatura.
A construção recusa chaves já derivadas por offset/escala e verifica a relação
entre a share local e o ponto público daquele participante.

O formato v1 tem tamanho fixo e checksum; o buffer que contém o segredo usa
Zeroizing. Arquivo 0600/create_new, fsync do arquivo e diretório. O chamador
estabelece primeiro um diretório privado durável. A leitura recusa symlink,
permissões públicas, tamanho diferente, escalar não canônico, papel inválido,
chaves públicas inválidas e identidade pública diferente da esperada.
O checksum detecta dano; não protege contra storage local hostil ou rollback.
O digest esperado vem do estado aprovado do chamador, não do arquivo recebido.

Restaurar exige a mesma cápsula, contexto/ponto do papel remoto, dificuldade e
recebimento. Reconstrói o roster, a chave local original e o vínculo de
recuperação. Não valida as equações da prova, não autoriza publicação e não
reconstrói/renova uma política temporal. A aceitação criptográfica da cápsula
continua a cargo do verificador; a janela original deve ser aplicada à parte.

## Cobertura

Passaram 25 testes Rust relacionados (quatro novos de estado local, quatro de
cápsula, quatro de vínculo direto e 13 do exemplo), Clippy all-targets com
-D warnings e build. O helper de processo aparece ignorado na lista principal
porque é executado duas vezes pelo teste pai. Evidência
`LOCAL-XMR-STATE-CHECKS.json`. A primeira rodada passou nos testes, mas o Clippy
recusou drop explícito de um objeto público sem destructor; foi substituído
por fim de escopo/movimentação. Histórico em `LOCAL-XMR-STATE-INITIAL-CHECKS.json`.

Os testes específicos cobrem ambos os papéis, troca de cápsula/tempo/contexto/
chave/dificuldade, offset/escala indevidos, cada byte corrompido ou truncado,
substituição com checksum recalculado, segredo inválido/não canônico e arquivos
ausentes/parciais/públicos/symlinks. Não há recriação automática de registro.

O teste de processo grava o estado e a cápsula, descarta os objetos originais e
executa outro processo só com os caminhos e bindings públicos. O filho restaura
a share e produz um ponto público derivado dela, comparado pelo pai. Repete para
os dois papéis; não fornece share por argumento/ambiente/stdout. A cápsula desse
teste é só uma fixture do codec, sem prova criptográfica ou moedas.

O modo nativo `direct-pair-abandon-local-receipt` agora persiste também
`local-xmr-recovery.record` antes dos depósitos. No custo da recuperação entram
o descarte dos objetos locais, leitura e reconstrução desse estado, além da
queda/restauração do Go, verificação da prova e abertura já exercitadas. A
restauração do estado local nesse cenário ocorre no MESMO coordenador Rust;
isso não é reinício integral do coordenador/daemon.

Próximo passo: levar a recuperação financiada e a devolução a um processo novo
que carregue também plano da transação, autorização e política temporal
originais. Nonces/sessões cooperativas, número global de quedas, preparação
independente, fundamentos de segurança e dom-interopd continuam pendentes.

## Ensaio financiado

PID 1250252, exit 0: **178,415 s** totais (parede **178,466 s**), recuperação
integral **58,509 s**, restauração Go **9,129 s**, abertura **49,311 s**.
A preparação da cápsula levou **65,443 s**, incluindo **37,640 s** na primeira
verificação do setup. A variação em relação aos ensaios anteriores não pode ser
atribuída à persistência da share como se fosse uma otimização de velocidade.
Condições de pressão de recursos foram registradas no provenance.

Recebimento 1790480170; início original +35 em 1790480205; devolução XMR
observada em 1790480264, antes do limite 1790480270. DOM lock219, inclusão220,
gasto221. Todos os outputs de devolução foram gastos; a mesma cápsula e prazos
foram mantidos. Passou nas metas observadas de 65 s para recuperação e 180 s
para o ensaio completo, com pouca folga, sem prova de limites universais.

Fontes/binários conferidos; PIDs 1250252/1250312/1251361 e grupo ausentes.
Session46505 terminou; não há ensaio pendente. Evidências
`DIRECT-PAIR-ABANDON-LOCAL-XMR-STATE-*` e `LOCAL-XMR-STATE-VERIFICATION.json`.
A restauração financiada ainda ocorre no coordenador Rust vivo. A evidência
de processo Rust novo é o teste separado de codec/estado, não este swap nativo.
