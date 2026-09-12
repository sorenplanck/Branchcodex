# V9 — trabalho de integração ainda incompleto

Este código é cumulativo sobre o V8. Ainda não cumpre a entrega solicitada
das 16 rotas funcionais. O bootstrap exige EVM+BTC; nenhuma opção deste
pacote remove os bloqueios que impedem funding sem autoridade de claim.

## Alterações reais desde V8

1. Driver Bitcoin Core → F7 → Contracts persistido → M.8 → autoridade de
   materialização do claim. Recolhe evidência em cada fase de assinatura,
   verifica a sessão contra a autoridade de funding antes de expor nonce e
   retém a autorização consumida durante falhas de transporte. Está escrito,
   mas **ainda não é chamado pelo bootstrap**.
2. Persistência de emissão/consumo com retomada sob um único lock. A retomada
   preserva os registros originais e recusa um segundo dono simultâneo. A
   revalidação compara novamente gate, roles, origem do segredo e âncora.
3. Transporte Bitcoin encerra e inutiliza a conexão após troca incompleta ou
   inválida. Uma nova conexão pode reutilizar as mensagens já persistidas;
   não se tenta retomar dentro de um frame parcialmente recebido.
4. Transporte XMR confere a resposta de funding contra o pedido mesmo quando
   o sidecar se autenticou. Txid, nonce, versão, valor ou spendability errados
   são recusados. Erros explicitamente temporários continuam temporários.
5. Cliente XMR usa conexão Unix não bloqueante, prazo absoluto compartilhado
   pelo handshake e frames, e apaga o buffer serializado com chaves privadas
   ao sair do escopo. O construtor permite um orçamento de até 180 segundos.

## Executar no Linux

Requer o toolchain fixado pelo repositório, dependências nativas de compilação
e Python com `cryptography`. A partir da raiz `dom-protocol`:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v9.py
```

O comando mantém os testes V8 e acrescenta testes de F7, Store, participantes
Bitcoin e sidecar XMR, além de build release e self-check do daemon. Para
rodar somente verificadores Python:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v9.py --offline
```

Os relatórios e logs ficam em `artifacts/daemon-v9/`. O runner para na primeira
falha, retorna código diferente de zero e registra o hash do código. Ele não
reescreve fontes ou atualiza hashes de proteção durante os testes.

Seis testes Rust novos foram escritos desde V8: dois sobre persistência F7,
um sobre conexão Bitcoin e três sobre sidecar XMR. Não foram executados aqui.
Os testes usam fixtures e sockets locais; não demonstram swaps em chains.

## Critérios de conclusão ainda abertos

| Critério solicitado | Estado neste código |
| --- | --- |
| Coleta de âncoras, F7, M.8/claim e recuperação | Driver e persistência escritos; integração no loop pendente |
| Inicialização por perna e F7 generalizado | Pendente; root continua exigindo EVM+BTC |
| Execução, refund e origem de revelação XMR | Pendente; reforço do transporte não implementa esses caminhos |
| Verificação das 16 rotas completas | Não realizada |

Os testes Rust que o usuário informou terem passado pertencem à versão que
ele executou. Não são evidência de compilação ou funcionamento deste código
adicionado posteriormente. A meta de qualidade não foi convertida em nota
10/10 ou aprovação de operação com fundos reais.
