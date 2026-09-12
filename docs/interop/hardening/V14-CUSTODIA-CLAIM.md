# V14 — código de claim universal, estado e revisão

Base cumulativa: V13, árvore `c31a4400a104206fccda78635a9ff9a94144a4c8`.
Este documento descreve código implementado, sem afirmar compilação ou operação das 16 rotas.

## Implementação

- `dom-adaptor`: reconstrução do output compartilhado a partir do funding autenticado, verificando compromisso, prova e capsule pela criptografia nativa.
- `dom-scriptless-store`: adaptação do template retido sob F7 fresca, segredo privado emprestado, verificação da assinatura/adaptor e transação DOM; publicação do registro de exposição antes do sucessor e de qualquer transmissão.
- A abertura do Store inclui a recuperação do sucessor exato da exposição. O plano de recuperação valida a proveniência antes de escrever e retém a identidade do arquivo de origem. Não cria outra transação nem outro nonce.
- Admissão exige recibo nativo econômico para o mesmo txid. Registro ausente, prefixo recuperável e contradição de bytes são tratados separadamente.
- `dom-actuator`: autorização da ação e lease, registro da tentativa, envio pelo RPC concreto, admissão nativa e espelho local. Após reinício, o mesmo proprietário pode atualizar a geração de posse e reparar o espelho sem novo RPC ou incremento artificial de tentativas.
- `production_final_claim_v14.rs`: worker que percorre adaptação, exposição, envio, admissão e staging de `0x12`. Recupera a caixa de saída nativa e revalida a identidade exata do transporte. Reconciliação no Relay não é confirmação do claim na chain.
- `ProductionF7RuntimeV12::step_final_claim_v14`: consome a conclusão da rodada nativa; observa novamente apenas a família selecionada imediatamente antes da primeira adaptação. Depois da exposição, recupera os mesmos bytes sem solicitar o segredo novamente.

## Decisão de custódia e congelamento de fontes

`ClaimSinkV14` é privado ao módulo nativo do Store. Guarda referências ao mesmo Store, à autoridade F7 consumida, à chain e à ação. Não tem construtor público, serializador, exportação de transação, acesso a chave ou persistência alternativa. Seu único método delega ao Store sob o lock nativo. O Store verifica novamente posse desta abertura, prazo da observação, papel do participante, template, funding, assinatura e sucessor antes da publicação. A capacidade de transmissão só sai depois dos dois registros duráveis.

Por isso, o par exato `OperationalClaimTransactionSinkV1 / ClaimSinkV14` foi acrescentado à lista explícita de implementações admitidas. Não foi adicionada permissão genérica nem removida uma verificação.

O hash congelado de `session_store.rs` acompanha a implementação do novo discriminador 26 e a recuperação de exposição. A comparação por funções com V13 está em `v14-authority-review.json`, dentro do ZIP. Todas as funções que contêm `Sponsor`, `require_strict_phase1` ou `is_strict_v1_authorized` permanecem byte a byte iguais. As funções preexistentes de `dom-actuator/contracts.rs` e `dom-actuator/store.rs` também permanecem iguais. Os novos métodos são adicionais. A atualização do hash registra uma mudança revisada de fonte; não é evidência de auditoria independente ou de teste Rust aprovado.

## Limites da entrega

O worker e a conexão com a rodada F7 existem, mas o root `production_run_universal.rs` ainda não monta e agenda esse conjunto de ponta a ponta. Permanecem pendentes a montagem integral do bootstrap, a via universal de recepção/observação do `0x12`, a integração de finalidade/reorg e a compensação DOM funcional condicionada ao funding XMR. A compensação ordinária insegura continua recusada. Não foi acrescentado um oráculo, uma prova fictícia de funding ou um contorno do bloqueio.

Os três critérios completos de V14 e as 16 rotas continuam sem atendimento. Os testes Rust adicionados não foram executados aqui. Os testes Python e a análise sintática estão registrados separadamente; não substituem compilação, testes nativos nem swaps.

## Compilar no ambiente de destino

Requer Linux (ou Linux no WSL2), Python 3.11+, a toolchain Rust do projeto e dependências nativas já disponíveis.

```sh
cd dom-protocol
python3 scripts/build_daemon_v14.py
```

O script executa Cargo com `--locked --release --no-default-features --features production`, preserva o log, exige um único artefato do binário e publica `dist/v14/dom-interopd` somente se o build terminar com sucesso. O relatório contém o SHA-256 do executável. Não inicia serviços, não recebe segredos e não executa swaps.

Para executar os novos testes Rust separadamente:

```sh
cargo test --locked -p dom-adaptor retained_shared_output_v14
cargo test --locked -p dom-scriptless-store v14_
cargo test --locked -p dom-interopd --features production missing_exact_funding
```

Esses testes têm escopo limitado. Não são uma campanha end-to-end das rotas.
