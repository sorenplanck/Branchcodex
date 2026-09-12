# Pedido público F6, assinatura externa e finalização

O comando `prepare-f6-artifact-v23` produz bytes públicos operacionais pelos
mesmos codecs usados pelo daemon. Não cria autoridade, admissão, chave, credencial,
atestado de terceiro ou transação. Nenhum RPC, carteira ou signer é chamado.
Todos os relatórios trazem `authenticated_authority: false`, inclusive depois de
finalizar: assinaturas válidas sob raízes **fornecidas** não substituem as raízes
confiadas e a admissão independente do daemon.

## Entradas e fronteira temporal

O JSON de entrada e os artefatos referenciados devem ser arquivos regulares 0600,
do usuário atual, sem hardlinks/symlinks, sob diretórios canônicos 0700. Caminhos
de arquivos são absolutos. O JSON e cada leitura pública têm limite de 262144
bytes; o snapshot final também precisa caber nesse limite. O buffer de leitura
tem reserva limitada única e é zerado ao terminar. Nunca forneça chaves privadas.

Não é necessário `AuthenticatedProductionInputsV1`, manifesto V11 completo ou
F6 preexistente. Os campos `composition_digest`, `profile_bundle_digest` e os
pins do registry são **entradas públicas explícitas do preparador da rota**.
Este comando não calcula uma composição substituta, não inventa uma prova
temporal e não insere valores temporários. Se esses pins ainda não existem,
o planejamento temporal/autenticação real deve produzi-los primeiro. A escrita
integral dessa pré-admissão não é substituída por este utilitário.

O formato tem `schema: "DOM-F6-PUBLIC-INPUT-V23"` e exige todos estes campos,
sem defaults econômicos:

| Campo | Conteúdo |
| --- | --- |
| `route` | `network_id`, `route_id`, `composition_digest`, `route_scope_digest`, `registry_digest`, `registry_epoch`, `profile_bundle_digest` |
| `economics` | `solver`, `inventory_binding_digest`, `bond_policy_hash`, `bond_asset_binding_digest`, `required_collateral`, `status_max_lifetime_seconds`, `valid_from_seconds`, `expires_at_seconds`, `max_evidence_age_seconds` |
| `authorities` | Bundle canônico `ProductionAuthorityBundleV1` existente: raízes registry, time-policy e time-evidence |
| `relay_roster` | Bundle canônico `ProductionRelayRosterBundleV1` existente |
| `upstream_terms`, `downstream_terms` | Bytes canônicos dos dois `SettlementTermsV1`, na ordem exata |
| `bond_authorities`, `status_authorities` | Dois `AuthoritySetV1` canônicos, independentes das raízes/participantes/Relay e entre si |
| `reserved_participant_keys` | Lista explicitamente fornecida de chaves públicas x-only, ordenada, distinta e não vazia; não é omitida nem inferida de outro papel |
| `signers` | Duas listas, upstream/downstream, de descritores públicos completos |
| `claim_profile` | Escolha explícita descrita abaixo |

Digests, IDs e chaves públicas de 32 bytes são arrays JSON de 32 inteiros entre
0 e 255. Não são textos hex nesses campos. Valores inteiros mantêm a precisão
do formato Rust, incluindo `required_collateral` u128; evite editores que
arredondem números JSON. Um descritor `signers` contém
`independent_authority_id`, `signer_index`, `signer_public_key`, `endpoint_uid`
e `endpoint` absoluto. Os índices seguem exatamente o conjunto bond fornecido;
os endpoints não são contatados por este comando.

Cada campo de artefato aceita uma das duas formas:

```json
{"source":"file","path":"/diretorio/privado/artefato.bin"}
```

```json
{"source":"canonical_hex","hex":"<bytes canônicos em hex minúsculo>"}
```

Para a primeira montagem sem templates, selecione explicitamente:

```json
{"profile":"native_enrollment"}
```

Isso produz **DOMF6A23**, com papéis/T/termos públicos, nunca um plano executável
de claim. O daemon ainda exige as duas sessões com enrollment/DLEQ reais e
templates provenientes do Store bilateral. Não há fallback automático para A07.

Quando o plano real já existe, `claim_profile` é:

```json
{
  "profile":"bound",
  "role_plan":{"source":"file","path":"/privado/role-plan.bin"},
  "sources":[
    {"source":"file","path":"/privado/upstream-source-scope.bin"},
    {"source":"file","path":"/privado/downstream-source-scope.bin"}
  ]
}
```

Isso produz **DOMF6A07**. O plano e os scopes são decodificados pelos codecs
reais e conferidos contra ambos os termos. As chaves Relay são derivadas do
roster; as chaves reservadas de chain são a união ordenada e sem sobreposição
das três autoridades do bundle, como exige o decoder. A lista de participantes
permanece explícita. A igualdade final com a admissão continua sendo do daemon.

## Preparar e retomar

```sh
dom-interopd prepare-f6-artifact-v23 \
  --input /privado/f6-input.json --output-dir /privado/f6-request

dom-interopd prepare-f6-artifact-v23 \
  --resume --request-dir /privado/f6-request
```

A saída deve ser nova. O comando publica atomicamente um diretório 0700 com:

- `public-input.json`: snapshot canônico com conteúdo de todos os artefatos,
  não referências a arquivos que possam mudar;
- `signing-prefix.bin`: prefixo binário exato que será assinado;
- `signing-request.json`: digest de assinatura, raízes fornecidas e marcador
  explícito de ausência de autoridade autenticada.

Resume recodifica tudo pelo encoder de produção e exige igualdade byte a byte
do snapshot, prefixo e relatório. Não repara corrupção nem relê os arquivos
originais. A publicação usa arquivos 0600, sincronização e rename NOREPLACE.
Após falha, preserve qualquer diretório `.preparing-v23`; ele não é apagado nem
completado automaticamente. Uma finalização parcial retida bloqueia resume.

## Assinar externamente e finalizar

Os donos das raízes registry devem revisar o prefixo e assinar externamente o
`signing_digest_hex` apresentado. É BIP340 sobre o digest com domínio já aplicado,
**não** sobre o texto hexadecimal, nem sobre um hash novamente aplicado. O domínio
A23 é diferente do A07. O processo não solicita nem recebe suas chaves privadas.
Os signers bond e status continuam separados: não são substitutos dessas raízes.

O arquivo de assinaturas é JSON 0600 de no máximo 8192 bytes:

```json
{
  "schema":"DOM-F6-EXTERNAL-SIGNATURES-V23",
  "signing_digest_hex":"<64 caracteres hex minúsculos do pedido exato>",
  "signatures":[
    {"signer_index":0,"signature_hex":"<128 caracteres hex minúsculos>"},
    {"signer_index":1,"signature_hex":"<128 caracteres hex minúsculos>"}
  ]
}
```

Os índices ilustrados não escolhem autoridades: use os índices reais, únicos e
crescentes, em quantidade suficiente para o threshold fornecido.

```sh
dom-interopd prepare-f6-artifact-v23 --finalize \
  --request-dir /privado/f6-request --signatures /privado/f6-signatures.json
```

Após verificação pelo mesmo verificador F6 do daemon, o comando publica
`finalized/authority.bundle` e `finalized/bundle-report.json`. O relatório contém
`bundle_digest_hex`, calculado pelo domínio exato do manifesto V11. Esse é o
digest para o manifesto final, não o digest assinado. O comando não altera o
manifesto nem monta o restante do state-dir.

Finalização repetida aceita somente os mesmos bytes completos. Outra combinação
de assinaturas, corrupção ou staging retido não sobrescreve o resultado. Resume
de uma finalização completa revalida suas assinaturas e o digest do bundle.
Isso prova a integridade do arquivo público, não prontidão mainnet, disponibilidade
negociada, autorização de funding ou execução de uma perna.

## Cobertura escrita para o comando real

O teste de integração `public_f6_cli_prepares_resumes_and_finalizes_external_signatures_without_signers`
invoca o binário `dom-interopd` produzido pelo Cargo em processos separados. Ele
prepara um pedido com artefatos públicos sintéticos, retoma após mudança do arquivo
de origem, verifica o threshold de duas assinaturas BIP340 externas, finaliza e
confere os bytes completos e o digest do bundle. As chaves sintéticas ficam no
processo do teste: nenhuma chave privada é enviada ao comando, e os endpoints
dos signers são deliberadamente inexistentes.

O mesmo cenário cobre assinatura insuficiente, índice duplicado, digest errado,
chave errada, replay exato sem regravar o arquivo, recusa de assinaturas válidas
mas diferentes após publicação e retenção de corrupção sem reparo. A cobertura
de biblioteca acrescenta permissões incorretas, hardlink, symlink, arquivo
inesperado, tamanho excedido e finalização parcial retida.

Esses cenários são código de teste, não evidência de execução por si só. A
aprovação deve ser registrada somente depois da execução no commit candidato.
Eles também não substituem a admissão F6 pelo daemon nem o teste bilateral
completo de funding, claim e recuperação DOM↔XMR.
