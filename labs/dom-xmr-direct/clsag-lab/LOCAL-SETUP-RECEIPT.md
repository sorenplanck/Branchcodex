# Retomada com comprovante de aceitação do verificador local

O ensaio anterior de restauração completa consumiu 85,247 s para recuperar,
acima dos 65 s assumidos. Só a recomputação do setup custou 40,279 s. O novo
caminho reutiliza a aceitação anterior desse setup, autenticada por uma chave
do verificador local. Não fornece prova remota de setup, autenticação de peers,
garantia de atraso RSA ou prova de segurança do protocolo.

## Fronteira de confiança

O supervisor cria `local-verifier-authority.key`, 32 bytes aleatórios, 0600,
create_new e fsync arquivo/diretório, em diretório próprio 0700 previamente
sincronizado. Só os processos de verificação recebem seu caminho absoluto em
configuração local `DXP1_LOCAL_SETUP_AUTHORITY_FILE`; o produtor não recebe
essa configuração. Nenhuma mensagem/JSON de peer pode fornecer uma chave.
Go exige arquivo regular, privado, tamanho exato e chave não zero, e recusa
symlink. Isso pressupõe supervisor/verificador e armazenamento local confiáveis;
não protege contra um escritor local que também controle a chave/configuração.

`direct-prepare-local-receipt` executa primeiro o mesmo check sequencial de
setup do caminho normal, depois todas as 256 equações da prova, contexto e
ponto esperados. SOMENTE então emite HMAC-SHA256, com domínio v1 e campos de
tamanho fixo: SHA-256 do setup exato, SHA-256 da oferta exata, contexto, ponto
público, dificuldade e recebimento original. Os dois inteiros usam u64 big
endian. O recebimento é o observado localmente pelo supervisor; o MAC não o
transforma em primeira divulgação autenticada.

O supervisor persiste o comprovante de 32 bytes em
`direct-capsule.setup-receipt`, com as mesmas regras de privacidade/fsync do
registro da cápsula, ANTES dos depósitos compartilhados. A chave, o comprovante
e a oferta não são exportados para os relatórios. Ausência/corrupção não cria
novo comprovante ou identidade como fallback.

`direct-restore-local-receipt` verifica o MAC com a autoridade configurada,
relê e valida a forma/dificuldade do setup e exige a oferta exata autenticada.
Só dispensa a repetição SEQUENCIAL da relação H do setup anteriormente aceito.
Reverifica toda a prova antes de permitir a abertura, que continua sequencial
com a mesma dificuldade. Preserva contexto, ponto, binding e recebimento.
O caminho normal de primeira aceitação não aceita campos de retomada nem
flag de "já verificado"; `direct-prepare` continua verificando tudo.

O formato CapsuleCheckpoint v2, sozinho, NÃO autoriza esse cache. O modo
anterior `direct-pair-abandon-solver-restart` continua repetindo setup/prova;
a opção nova é `direct-pair-abandon-local-receipt`. Não há fallback implícito
entre elas, nem alteração de prazo quando a retomada é mais cara.

## Verificação

Passaram 35 testes Rust relacionados, com nova execução dos 13 testes do
exemplo depois de acrescentar o início tardio, Clippy all-targets -D warnings e
build. Evidências `LOCAL-SETUP-RECEIPT-{RUST,LATEST-START}-CHECKS.json`.

Passaram 24 testes Go, vet e build (`../recovery-audit/LOCAL-SETUP-RECEIPT-GO-CHECKS.json`).
Os três novos testes cobrem arquivos de autoridade inválidos/ausentes/públicos,
symlinks, chave trocada, cada campo do MAC alterado, tentativa de chave no wire,
setup inicial falso, comprovante recusado para prova falsa, oferta substituída,
primeira aceitação separada da retomada e abertura real depois da restauração.
Um teste fabrica deliberadamente um MAC com a chave DE TESTE para uma prova
inválida: a retomada ainda a rejeita. Isso comprova que verificar o MAC não
substitui verificar as equações da prova.

O cenário nativo novo espera até `recebimento_original + 35` antes de encerrar
o verificador e iniciar a recuperação. A espera entra no total; encerrar,
carregar, autenticar, revalidar a prova, abrir e conferir a share entram no custo
de recuperação. Exige esse custo <=65 s e mantém os limites absolutos de
devolução originais. O início é medido em segundos inteiros, como a fixture
anterior; isso não estabelece um limite de relógio/scheduling em produção.

Continuam vivos o supervisor Rust, os nós, roster e share local. O teste mata
o verificador enquanto ele espera a abertura, não durante um solve parcial.
Persistência dessas outras partes, número global de reinícios, setup justo,
participantes independentes, fundamentos temporais/criptográficos e integração
ao dom-interopd permanecem pendentes.

## Resultado nativo

PID 1084776 terminou com exit 0, sem timeout: **219,839 s** totais, incluindo
preparação e espera deliberada até o último segundo permitido para iniciar.
A recuperação integral levou **44,756 s**, dentro dos 65 s assumidos;
restauração **9,796 s**, revalidação da prova **9,702 s**, abertura **34,936 s**.
O cache autenticado dispensou apenas a recomputação sequencial do setup.

Recebimento original 1790478990; início 1790479025 (= original +35);
devolução XMR observada em 1790479070, antes do limite original 1790479090.
DOM: altura de bloqueio 217, devolução incluída em 218 e gasto em 219.
Todos os outputs de devolução foram gastos depois. Cápsula, comprovante,
autoridade e prazos permaneceram iguais; nenhum produtor/prova novo.

O total excede 180 s. A primeira verificação sequencial do setup levou
70,089 s e a preparação completa da cápsula 103,502 s nesta execução.
Não atribuímos a variação a uma causa ainda não medida e não repetimos o
mesmo ensaio para selecionar um tempo menor. A passagem no orçamento local
de recuperação não estabelece um limite honesto universal ou SLA.

Evidências `DIRECT-PAIR-ABANDON-LOCAL-RECEIPT-*` e
`LOCAL-SETUP-RECEIPT-VERIFICATION.json`. Hashes de fontes/binários conferidos;
PIDs 1084776, 1085002 e 1109383 e grupo do ensaio ausentes ao terminar.
