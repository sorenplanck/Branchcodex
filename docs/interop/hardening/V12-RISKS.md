# V12: limite material da compensação DOM/XMR

Este candidato contém implementação de custódia, transmissão e observação;
isso não demonstra que o protocolo de compensação atual seja economicamente
seguro. A inicialização operacional continua recusada pelo bloqueio global.
Não se deve remover esse bloqueio para testar com fundos reais.

## Ataque concreto que o daemon sozinho não resolve

No grafo atual, C é o colateral DOM, D é sua saída de cancelamento, Hc permite
cancelar C e Hp permite gastar D pela transação de compensação. Antes de C ser
publicado, os participantes retêm cancelamento e compensação já assinados.

1. A parte que deposita DOM confirma C, conforme a ordem exigida para proteger
   o futuro depositante de XMR.
2. A contraparte recebe a compensação assinada, mas **não deposita XMR**.
3. O depositante DOM desaparece antes de publicar seu refund que revela U.
4. A contraparte publica o cancelamento após Hc e a compensação após Hp,
   diretamente no nó DOM, sem executar este daemon.
5. DOM aceita a compensação pelos scripts e assinaturas existentes. O atacante
   recebe DOM apesar de não ter travado XMR.

Finalidade DOM, margem de preço, prazos mais longos, journaling e a exigência
de verificar XMR no daemon não alteram o passo 5: a regra executada pela chain
DOM não exige prova de que o principal XMR foi efetivamente depositado.
Portanto uma opção de configuração, um novo booleano ou um marcador no banco
não são correções para este ataque.

## O que a implementação V12 efetivamente controla

- O depositante XMR importa bytes assinados em arquivo privado retido. O
  verificador nativo confere hash, saída derivada com a view key, compromisso,
  quantia, ausência de lock adicional e teto de taxa. A wallet prepara com
  `do_not_relay`; nenhuma share de gasto combinada é necessária para funding.
- A transmissão controlada registra a identidade exata em custódia durável e
  verifica novamente C canônico, não gasto, suficientemente confirmado e ainda
  dentro da janela de claim. Só então transmite os mesmos bytes ao monerod.
- A recuperação escreve sua intenção antes do RPC e repete a observação após
  a persistência. Refund que revela U exige cancelamento confirmado e folga
  estrita antes de Hp. Compensação não revela T nem U.
- O daemon exige evidência nativa recente de funding XMR antes de transmitir
  compensação ou aceitar o resultado econômico na rota. Evidência de ausência
  não é uma autorização, e resposta para outro txid é recusa dura.
- O ledger registra `DomCompensatedV12`, separadamente de um refund XMR. Um
  evento desserializado ou digest fornecido por um chamador não pode produzir
  esse resultado; o consumidor exige autoridade nativa e observação recente.
- Reinício reabre bytes e identidades exatos e reconsulta as chains. Marcadores
  persistidos nunca se transformam sozinhos em prova de finalidade.

Esses controles protegem a execução honesta e a recuperação local. Eles **não
revogam uma transação de compensação já entregue à contraparte**. A observação
Monero ainda depende do modelo de confiança declarado para nós e sidecar.

## Condição necessária para remover o bloqueio

A condição de elegibilidade da compensação precisa ser verificável pelo
próprio mecanismo que autoriza o gasto DOM, inclusive contra uma contraparte
que publica bytes diretamente. A evidência deve vincular a transação XMR,
endereço compartilhado, quantia e finalidade à sessão e aos termos, sem
conceder à outra parte acesso prematuro à share privada. A solução também
precisa especificar reorgs, disponibilidade e quem pode fabricar a evidência.

Este candidato não inventa uma prova entre chains nem afirma ter implementado
uma verificação de consenso Monero em DOM. Sem esse mecanismo e uma revisão
do protocolo resultante, não há base para anunciar as 16 rotas concluídas,
operação 10/10 ou segurança de compensação unilateral com dinheiro real.

## Evidência local desta entrega

Foram escritos testes Rust de custódia, janelas de recuperação, codec legado,
reabertura do ledger e distinção de compensação/refund. A análise sintática
local não substitui compilação, execução desses testes ou swaps completos.
O ambiente desta entrega não possui Cargo; os testes Rust precisam ser
executados no ambiente do operador. Nenhum resultado aprovado é presumido.
