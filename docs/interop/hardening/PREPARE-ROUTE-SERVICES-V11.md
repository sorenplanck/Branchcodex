# Preparar serviços por perna sem abrir clientes de rede

O binário de produção oferece `prepare-route-services-v11` para escrever
`production-route-services.v8.json` usando o mesmo codec que o daemon lê.
O comando não acessa RPC, cookie Bitcoin, carteiras ou chaves e não assina,
financia ou transmite transações. O número V11 identifica a preparação para
o bootstrap universal; o documento de serviços continua com versão 8.

## Uso

Compile o binário com `--no-default-features --features production`.
No diretório privado já existente, execute:

```sh
dom-interopd prepare-route-services-v11 --state-dir /caminho/privado/dom-state < services.json
```

O diretório deve ter caminho absoluto canônico, pertencer ao usuário executor
e ter permissões 0700. A entrada é um único objeto JSON, até 131072 bytes,
seguido por EOF; o comando recusa terminal interativo. IDs são arrays de
32 bytes, não strings hexadecimais. As pernas aparecem na ordem upstream,
downstream e precisam ter settlements distintos.

Exemplo **somente de formato**, com identificadores sintéticos e endpoints
locais ilustrativos. Substitua os identificadores pelos valores dos termos,
composição e registro reais autenticados; este exemplo não autoriza uma rota:

```json
{
  "version": 8,
  "route_id": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
  "composition_digest": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
  "registry_digest": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
  "legs": [
    {
      "settlement_id": [4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
      "chain_id": [5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],
      "service": {
        "family": "XMR",
        "endpoints": ["http://127.0.0.1:18081"],
        "quorum": 1
      }
    },
    {
      "settlement_id": [6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6],
      "chain_id": [5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],
      "service": {
        "family": "XMR",
        "endpoints": ["http://127.0.0.1:28081"],
        "quorum": 1
      }
    }
  ]
}
```

Cada objeto `service` aceita somente os campos da família selecionada:

| Família | Campos adicionais |
| --- | --- |
| BTC | `endpoint`, `wallet`, `cookie` (caminho absoluto; não lido na preparação) |
| EVM | `endpoint`, `refund_timeout_seconds` (1 a 300) |
| SOL/XMR | `endpoints`, `quorum` (maioria estrita conforme o validador existente) |

O codec mantém as restrições existentes de endpoints e quórum. Não inclua
credenciais, chaves, autenticação na URL ou campos de outra família.
A quantidade de nós, redes e demais escolhas ainda serão comparadas com os
perfis e deployments autenticados quando `run` carregar a configuração.

## Publicação e recuperação

O comando cria um arquivo temporário 0600, sincroniza seu conteúdo e o
diretório, e publica por renomeação atômica sem substituição. A saída padrão
contém somente um relatório de metadados: esquema, nome fixo do arquivo,
tamanho, duas posições e `network_access: false`; não imprime endpoints.

Um destino existente é sempre recusado, mesmo com conteúdo idêntico. Links
simbólicos, hardlinks e um temporário preexistente não são sobrescritos.
Após interrupção, preserve e inspecione
`.production-route-services.v8.json.preparing-v11` e o destino antes de
qualquer intervenção: o comando não presume que um arquivo incompleto pode
ser removido nem substitui automaticamente a configuração.

No bootstrap V11, a ausência/corrupção deste documento é uma recusa: não
há fallback para o arquivo legado que exige EVM e Bitcoin.

## Limites

Este escritor entrega somente configuração pública de serviços. Não produz
credenciais V4, shares, registry assinado, termos negociados, atestação de
programa/deployment, evidência temporal ou autorização F6/F7. Não substitui
a admissão autenticada do runtime nem comprova os fluxos das 16 rotas.
As autoridades privadas de terceiros continuam externas e obrigatórias.
