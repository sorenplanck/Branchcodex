# V20 — estado de desenvolvimento

Base imediata: `DOM-interop-v19-codigo.zip`, commit local `ff328ca3aaca0107c38a1a3fa4526054ca3a28ee`.

A V20 é continuação da V19. A V18 é somente a origem histórica da V19; não foi usada como uma nova base para refazer ou descartar a V19. As alterações V20 foram acrescentadas em commits descendentes da V19.

Regra de continuidade: cada próxima versão deve partir da versão imediatamente anterior, preservando seu código e suas correções. O patch desta entrega é V19 → V20; os arquivos auxiliares da V19 são mantidos no pacote como histórico.
Branch local: `interop/v20-native-funding-bootstrap`.

**Este checkpoint não encerra as 16 rotas. Não é uma declaração de prontidão operacional ou nota 10/10.**

## Código escrito nesta etapa

- Gate F7 EVM/SOL construído pelo bootstrap universal usando as provas, os templates, os termos, os papéis e o refund autenticados no próprio Contracts Store.
- Autorização durável de assinatura de funding após os dois votos DSC1 0x17. Reutiliza a rodada nativa de seis mensagens e o vault existente.
- Agendador de funding chamado pelo runtime universal; replay do outbox; devolução do vault ao próximo estágio.
- Materialização, persistência de custódia no controle DOM e transmissão do funding F7 pelo filho DOM do coordenador, com o cliente DOM existente.
- Leitura de finalidade do funding sem depender de uma emissão anterior de autorização de claim.
- Carregamento, transmissão e autenticação do refund simples EVM/SOL pelo caminho do executor DOM.
- Guarda temporal antes de nova operação privada e antes da transmissão. Agregação e retenção de assinaturas já emitidas continuam possíveis após o prazo.
- Recuperação dos cortes entre publicação da autorização, avanço de sessão, publicação dos bytes assinados e avanço para FundingBroadcast.
- Bootstrap distingue seu refund concluído das mensagens de assinatura dos estágios posteriores.
- Código de regressão para cortes de staging, artefato órfão, substituição de sessão, adulteração de bytes e distinção entre falha de transporte e evidência inválida.
- Leitura da identidade exata do funding EVM/SOL pelo mesmo executor usado pelo coordenador. EVM reaudita a operação e sua cadeia de tentativas; SOL reconstitui a mensagem assinada e verifica a custódia. Ausência não encobre adulteração. A leitura funciona a partir do banco existente após reinício, sem cache volátil obrigatório.
- Agendamento da rodada de claim F7 EVM/SOL no loop universal e no dono Stage-12. Usa a share de claim do bootstrap e o vault devolvido pelo funding; conecta os observadores da chain selecionada ao produtor existente das seis mensagens e da pré-assinatura 0x0f. Reobserva âncoras antes das operações de assinatura.
- O encerramento da janela de claim não impede o driver de continuar para refund. Reinício é exigido se uma abertura falhar depois de consumir os donos privados em memória.
- Validação do escopo da primeira revelação generalizada para EVM/BTC/SOL/XMR com DOM como origem nesse modo. A admissão XMR continua dependendo do mecanismo de recuperação; essa generalização não concede autoridade para funding XMR.
- Regressão escrita para identidade EVM ausente/preparada/assinada, reinício e substituição, e para seleção das quatro famílias no escopo de primeira revelação.

## Ainda não concluído

- Integração da adaptação, exposição durável e transmissão do claim universal no filho DOM do coordenador. A nova chamada da rodada de assinatura não fecha essa parte. Ainda falta o dono do segredo de origem ligado à ação de primeira exposição e o consumo da conclusão pelo executor.
- Recuperação operacional integral desse claim, incluindo o caminho posterior à exposição no runtime. Os componentes V14/V15 existentes não demonstram, isoladamente, essa montagem completa.
- Consumo do resultado M.8 pelo produtor DOM e conclusão da transmissão/recuperação de claim no runtime real.
- Compensação XMR condicionada de maneira que não possa ser gasta sem funding XMR. As recusas existentes permanecem; não foram removidas nem substituídas por confiança em um booleano de configuração.
- Inicialização e execução integral das rotas XMR e fechamento das 16 combinações.

## Verificação

Nenhum build, teste Rust, daemon, swap ou ferramenta de teste do projeto foi executado nesta etapa, conforme solicitado pelo usuário. O trabalho foi conferido por leitura do código e comparação das alterações; os testes acrescentados são somente código ainda não executado. O relato de compilação/testes da V18 é do usuário e não se estende automaticamente à V20.

As duas primeiras revisões Git são importações locais do ZIP, não commits publicados no repositório oficial. Não houve push, PR ou implantação.

## Caminho conectado na fonte

`production_run_universal::run` chama Stage-12 para funding e claim em cada posição. O bootstrap fabrica o gate F7; os votos 0x17 autorizam a rodada de funding; o Store retém as seis mensagens e a transação final; o executor DOM usa essa custódia para materializar e transmitir funding/refund. O leitor do router consulta a custódia externa exata; Stage-12 inicia a rodada de claim com as âncoras reais e o material privado do bootstrap. **A saída de claim ainda precisa da integração de adaptação/exposição/transmissão acima.**

A combinação de famílias aceita pelo escopo de seleção não equivale a uma rota executável. Nenhuma das 16 combinações é declarada concluída ponta a ponta nesta entrega.
