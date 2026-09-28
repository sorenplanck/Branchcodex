# Cápsula pública persistida e verificador novo após queda

O modo `direct-pair-abandon-solver-restart` grava a cápsula verificada ANTES
dos depósitos compartilhados DOM e XMR. Depois dos depósitos, descarta a share
remota, encerra o processo Go verificador com SIGKILL, restaura outro processo
do arquivo e abre a cápsula para devolver XMR. O minerador DOM continua
avançando durante toda essa retomada. Supervisor Rust, roster, share local,
material das transações e nós permanecem vivos: não é restart completo do
coordenador nem integração ao dom-interopd.

`src/capsule_checkpoint.rs` registra contexto, ponto público, binding SHA-256
da oferta aprovada, recebimento original em segundos, dificuldade, medições
originais de preparação, setup e oferta públicos. Não registra escalar secreto,
fatores RSA ou nonce do produtor. O registro é participante-privado (0600),
create_new, arquivo/diretório sincronizados; o cenário estabelece previamente
um diretório 0700 durável. Reabertura tem leitura limitada, checksum e formato
canônico. Não recria nem conserta registro ausente, parcial ou inválido.

O digest esperado vem do vínculo de recuperação aprovado, não do arquivo.
Contexto/ponto/recebimento também são comparados com a operação no cenário.
Isso pressupõe armazenamento local confiável; checksum não autentica metadados
contra escritor hostil ou rollback. A leitura do registro NÃO equivale à
aceitação criptográfica: o processo Go novo repete a verificação sequencial
do setup e todas as 256 equações da prova antes de abrir.

O instante original não muda. Para o relatório de tempo decorrido, o processo
restaurado usa o segundo original arredondado para baixo, portanto inclui até
um segundo adicional em relação ao instante monotônico original. Isso não
transforma recebimento local em primeira divulgação autenticada nem resolve
rollback de relógio. Leituras, término/início de processos, setup, prova,
abertura e vínculo da share entram no custo completo de recuperação; o gate
nativo continua conferindo o limite absoluto original. O custo observado
também deve ser comparado aos 65 s assumidos pelo modelo, separadamente de
terminar antes do limite absoluto por ter começado mais cedo.

## Falha inicial e correção

PID 1057817 terminou com exit 101 em 76,667 s, após ambos os depósitos e
SIGKILL do verificador antigo. A restauração tentou extrair o setup usando
`serde_json::Value` sobre toda a oferta; seus inteiros criptográficos ultrapassam
a faixa desse decoder. Não houve nova verificação nem abertura. Evidências
`DIRECT-PAIR-ABANDON-SOLVER-RESTART-INITIAL-FAILURE-*` e resumo JSON.
Grupo de processos encerrado. Não considerar essa tentativa uma recuperação.

O formato v2 guarda setup e oferta como strings opacas separadas. O Go exige
que o setup recebido seja idêntico ao contido na oferta durante a verificação;
não há conversão nem redução de inteiros no Rust. Os registros v1 da tentativa
falha não são migrados ou aceitos automaticamente. Quatro testes do registro
cobrem corrupção/truncamento/substituição, limites, ponto, NaN/infinito,
permissões/imutabilidade e inteiros de milhares de dígitos. A suíte relacionada
tem 35 testes Rust; resultados em `CAPSULE-COLD-RESTART-CHECKS.json`.

## Resultado corrigido: funcional, acima dos orçamentos

Passaram os 35 testes Rust, Clippy all-targets -D warnings e build separados.
O ensaio nativo PID 1062947 terminou com exit 0 em **194,762 s** (watchdog
194,773 s), acima de 180 s. A preparação de saldos individuais levou 38,766 s,
contra 19,399 s na tentativa inicial; não atribuir todo o tempo ao restart.

Depois dos dois depósitos, o verificador 1063596 foi encerrado por SIGKILL.
O processo 1063912 reabriu o registro v2 inalterado. Revalidação do setup:
**40,279 s**; prova: **8,989 s**; restauração total: **49,304 s**; abertura:
**35,939 s**. Recuperação completa, incluindo encerramento/início e checks:
**85,247 s**, ACIMA dos 65 s assumidos no modelo original.

O recebimento original 1790477388 foi preservado. A devolução XMR foi observada
em 1790477485, três segundos antes do limite absoluto original 1790477488.
Isso ocorreu porque a recuperação começou cedo: NÃO valida o orçamento
relativo de 65 s nem o caso de começar no último instante permitido. DOM foi
devolvido na altura 220, gasto na 221, com devolução original travada em 219.
Os outputs XMR também foram gastos. Não houve nova geração de prova, share
privada enviada ao solver ou aumento de dificuldade/janela para passar.

Evidências `DIRECT-PAIR-ABANDON-SOLVER-RESTART-*` e
`CAPSULE-COLD-RESTART-VERIFICATION.json`, com ambos os critérios temporais
explicitamente falsos. Fontes/binários conferidos; PIDs/grupo encerrados,
session 70530 exit 0. O ensaio não deixou processo a retomar. A falha inicial
permanece preservada, sem selecionar somente a execução bem-sucedida.

Próxima lacuna: reduzir a recomputação do setup na restauração com uma
fronteira de confiança explícita para evidência persistida ANTES do funding.
Não aceitar um flag externo de "já verificado", reutilizar prazo novo ou
ampliar o orçamento apenas para acomodar o resultado. Avaliar cache de estado
aceito sob o modelo local existente sem confundi-lo com prova criptográfica
para participantes remotos; qualquer caminho novo precisa manter o vínculo
exato à oferta aprovada e separar recuperação de primeira aceitação.

Preparação justa/distribuída, persistência do roster/share local e solver em
andamento, autenticação, orçamento global de reinícios, limites adversariais,
prova de segurança completa e dom-interopd permanecem pendentes.
