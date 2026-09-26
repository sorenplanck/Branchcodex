# Prazos desde a divulgação e relógios diferentes

Esta análise é parte do mecanismo novo DOM↔XMR. Não autentica uma preparação,
não calibra um adversário e não autoriza depósitos. Explicita as premissas que
faltam entre as primitivas já executadas e um protocolo seguro.

## Uma altura não vale 120 segundos de proteção

O código nativo exige timestamp estritamente maior que o do pai e limita
timestamps futuros. A integração da cadeia chama ambas as verificações:
`crates/dom-chain/src/chain_state.rs`, inclusive no processamento de forks.
As verificações estão em `crates/dom-consensus/src/block.rs`. Mainnet/regtest
usam 120 segundos de tolerância; testnet usa 30. O buffer adicional de blocos
futuros adia o processamento e não altera a tolerância de aceitação.

Se uma âncora de altura `h` e timestamp `s` permanecer ancestral da cadeia,
um bloco de altura `H > h` terá timestamp no mínimo `s + (H-h)`. Com tolerância
futura `F` e relógio do validador no máximo `C` segundos adiantado em relação
ao relógio dos prazos, sua aceitação não pode ocorrer antes de:

```
E_DOM = max(0, s + (H-h) - F - C)
```

Isso é uma restrição inferior condicional, não uma previsão de chegada de
blocos. Reorganizar para uma cadeia que não contém a âncora invalida a premissa.
Um timestamp público também não prova que o relógio do validador é correto.
Não há aqui um limite superior para a cadeia chegar à altura de devolução.

`clsag-lab/src/time_bounds.rs` implementa a conta com aritmética verificada,
rejeita altura já atingida e calcula a menor altura cujo limite fica estritamente
depois de um prazo. O tipo `AssumedDomAnchor` é intencionalmente uma premissa,
não uma âncora autenticada. Quatro testes exercem os validadores temporais
nativos, as fronteiras de igualdade e overflow. Os headers desses testes são
fixtures somente para timestamps; não demonstram PoW ou finalidade.

Exemplo: âncora `(h=10, s=1000)`, `F=120`, `C=5` e prazo 1100 exigem pelo
menos `H=236` para produzir `E_DOM=1101`. Uma altura 12 não oferece esse limite.
Multiplicar duas alturas pelo intervalo **alvo** de 120 segundos não é válido:
os validadores de timestamp aceitam os timestamps 1001 e 1002 com relógio 1000.
A dificuldade/PoW pode impor um custo probabilístico, mas não foi modelada
nem usada como uma garantia determinística de tempo nesta conta.

## Abertura adversarial e recuperação honesta têm limites distintos

O modelo anterior usava um prazo único por moeda. Agora `model.py` distingue:

- `recovery`: primeira disponibilidade possível para o adversário;
- `honest_recovery`: última disponibilidade garantida ao participante honesto,
  **assumida**, sem derivá-la de um benchmark médio;
- `funded_at`: disponibilidade fixa assumida dos inputs;
- `ready_at`: instante em que as ofertas ficam utilizáveis, após os inputs.

Todos os instantes pertencem ao mesmo eixo abstrato, iniciado na divulgação
da cápsula. Não são reiniciados depois da preparação. O modelo não demonstra
o protocolo justo de depósito/entrega nem maturidade; essas etapas continuam
representadas por premissas de disponibilidade em instantes fixos.

Para a ordem XMR→DOM, com A depositando DOM e conhecendo inicialmente o segredo,
as margens conservadoras exploradas são:

```
ready_at + I_XMR < E_XMR
L_XMR + I_XMR + O + I_DOM < E_DOM
```

`E_XMR` é a abertura adversarial mais cedo; `L_XMR` é a recuperação honesta
mais tarde. `I` limita resolução por inclusão ou conflito, não garante que a
transação honesta vença. `O` inclui observação e reação. Depois de iniciar a
devolução, a parte honesta continua reagindo a uma claim concorrente.

## Contraexemplo reproduzível

Com `E=(9,5)`, `I=(1,1)`, `O=1`, funding em `(2,2)` e ofertas prontas em 3,
supor recuperação honesta igual à adversarial não encontra perda na exploração.
Ao modelar `L=(11,7)`, a mesma composição permite:

1. Em 7, B publica devolução XMR.
2. Em 8, A publica sua claim XMR retida; ela vence e recebe XMR.
3. Em 9, B reage publicando claim DOM; A também publica devolução DOM.
4. A devolução DOM vence e A termina com as duas moedas.

O cenário com `E=(12,5)`, `L=(14,7)` não encontrou perda para nenhum dos três
casos de corrupção que deixam um participante honesto, dentro dessas premissas
e do domínio finito. Sem adversários, exige troca efetiva, não somente cancelamento.
Outro controle atrasa `ready_at` de 3 para 4 e esgota a janela de início: os
honestos devolvem os fundos sem revelar o segredo. Fingir que a divulgação
ocorreu no funding reabre artificialmente a janela e representa outra premissa,
não uma correção do protocolo.

Reprodução e resultado:

```sh
python3 -B -m unittest discover -s labs/dom-xmr-direct -p 'test_*.py' -v
python3 -B labs/dom-xmr-direct/timing_audit.py
```

Os 22 testes Python passaram. O relatório
[PREPARATION-TIMING-RESULT.json](PREPARATION-TIMING-RESULT.json) registra políticas,
estados explorados e o contraexemplo completo, com `atomic_swap_proven: false`.

## Ligação da busca completa à altura DOM

`AssumedXmrRecoveryWindow`, em `clsag-lab/src/time_bounds.rs`, agora conserva
o binding do desafio, a divulgação original e o número de candidatos atrasados
derivado do próprio desafio. Não aceita trocar esse número pelo de tentativas
bem-sucedidas em um benchmark. Para o cliente serial anterior, as contas eram:

```
E_XMR = divulgação + atraso_adversarial_mínimo_assumido
L_XMR = início_honesto_até + candidatos * (verificação + solve) + overhead
ready_at + I_XMR < E_XMR
H_DOM = menor altura cujo E_DOM > L_XMR + I_XMR + O + I_DOM
```

Custos e atraso continuam **premissas fornecidas**, não limites comprovados.
Overhead deve incluir reconstrução e interrupções admitidas; verificação deve
incluir abertura do processo, parsing e comunicação. Falta estabelecer esses
valores, a recuperabilidade e as premissas da cadeia. A função não autoriza
depósitos nem é usada como aprovação nos ensaios financiados.

A sessão pública `solve-session` verifica a oferta uma vez e resolve candidatos sob
demanda. `from_session_costs` representa esse caminho sem supor paralelismo:

```
L_XMR = início_honesto_até + verificação_pública_única
        + candidatos * (solve + conferência_individual) + overhead
```

`from_serial_costs` conserva a conta histórica de um processo/verificação por
tentativa para comparação. As duas funções usam o mesmo conjunto completo e
o mesmo prazo original; a economia da sessão é somente a verificação pública
repetida. Dois testes adicionais conferem essa diferença exata, altura estrita,
contagem, custos zero e overflow. Nenhuma das fórmulas estabelece por si só
os custos máximos ou o mínimo adversarial.

O cliente preparado agora usa `prepare-session`: verifica o setup antes da
divulgação dos puzzles e mantém esse verificador vivo; prova de faixa,
aberturas e Feldman são conferidos antes do funding. `from_prepared_costs`
representa somente a fase de recuperação desse processo já preparado:

```
L_XMR = início_honesto_até + candidatos * (solve + conferência) + overhead
```

Os custos anteriores continuam na preparação e no total medido. A divulgação
original e os 99 candidatos permanecem na conta; mover a verificação não
reinicia `E_XMR`. Um teste adicional confirma isso, inclusive rejeição de
janela inicial esgotada e overflow. Reinício do verificador não está coberto
por essa premissa e exigiria contabilizar revalidação/acesso ao material.
Separar os processos locais não autentica o setup nem comprova atraso mínimo.

Quatro testes adicionais verificam a contagem integral até 256 candidatos,
binding exato, janela consumida pela preparação, altura mínima estrita,
premissas impossíveis e overflow. Exemplo puramente hipotético: seis puzzles,
três candidatos, dois segundos por tentativa e um de overhead dão sete segundos
de recuperação; contar só uma tentativa daria três. Com a âncora `(10,1000)`,
tolerância DOM 120 e três segundos de margens de claims, a altura exigida sobe
de 137 para 141. As hipóteses numéricas deste exemplo não são medições.

A [análise do orçamento de busca](recovery-audit/README.md#orçamento-da-busca-após-aceitação)
mostra por que o perfil de 198 puzzles deve admitir os 99 candidatos no cenário
Q=2^64/erro 2^-128 para esse componente. A sessão elimina a repetição da prova
pública, mas conserva a conferência de cada candidato. Um prazo baseado apenas
em duas tentativas não preserva esse limite.

## Conta separada para a cápsula direta

`from_direct_costs` recebe um `XmrDirectRecoveryLink`, não um desafio
cut-and-choose. Conserva seu binding de roster/papel/cápsula e conta uma
abertura mais checagem e overhead. Não altera o orçamento de 99 candidatos
da construção anterior. A verificação de backend e seu atraso são premissas
externas: construir o vínculo não as comprova.

```
L_XMR_direto = início_honesto_até + abertura_e_checagem + overhead
E_XMR_direto = divulgação_original + atraso_adversarial_mínimo_assumido
```

As duas construções usam a mesma conta conservadora de altura DOM e a mesma
condição estrita de janela inicial. Um teste adicional confirma uma abertura,
binding exato, manutenção dos 99 no backend antigo, rejeição de janela
esgotada, custo zero e overflow. São 12 testes de prazos aprovados nesta etapa;
nenhum dos valores hipotéticos usados neles foi inserido como permissão de
depósito no ensaio financiado.

O modo `xmr-direct-recovery` exercita somente moedas geradas em monerod local
isolado, com `timing_admission_used=false` e `safe_bilateral_window_proven=false`.
Ele testa a devolução nativa com a share recuperada, não uma margem segura
entre claim XMR, reação do peer e altura DOM.

## Obrigações que continuam abertas

### Ordem DOM-first

`required_dom_refund_height` usa a ordem XMR-first. A integração inversa agora
usa `required_dom_refund_height_for_dom_first`, que exige:

```
ready + I_DOM + O + I_XMR < E_XMR
```

Aplicar somente `ready + I_XMR < E_XMR` depois de publicar DOM permitiria que
XMR fosse recuperado enquanto a contraparte ainda observa DOM. O novo teste
mostra uma janela aceita para XMR-first e recusada para DOM-first, verifica
igualdade recusada, origem do relógio, custos zero e overflow. A altura final
conserva a proteção anterior contra recuperação tardia, sem reiniciar prazos.
São 13 testes de prazos após essa adição; as premissas continuam condicionais.

O ensaio integrado e suas hipóteses explícitas estão em
`clsag-lab/DIRECT-PAIR-REGTEST.md`. Ele usa a âncora de um cabeçalho canônico do
nó local para escolher a altura, mas não prova atraso adversarial ou limites de
rede. O helper respeita o relógio do consenso ao minerar até essa altura.

O solve observado de cerca de um segundo não fornece `E_XMR`. Tampouco fornece
`L_XMR` em condições adversariais: esse limite deve incluir verificação, acesso
ao material, computação, interrupções permitidas e eventual busca de outra share
quando uma abertura não coincide com Feldman. O bridge atual e o desafio não
provam, sozinhos, esses limites.

A [auditoria de busca XMR](clsag-lab/RECOVERY-SEARCH-AUDIT.md) já reproduziu
uma cápsula aceita com primeira abertura inválida e recuperação financiada
pela segunda. A busca registra todas as tentativas e seu custo; essa medição
ainda não fornece o limite honesto em condições adversariais.

Antes de financiar ou entregar assinaturas irreversíveis, uma implementação
precisa conferir as margens restantes e a mesma cápsula/âncora/rede/plano
autenticados. Um timeout local não altera os bytes já entregues ao adversário.
Uma política que sempre recusa também não cumpre o objetivo: ainda precisamos
de um perfil concretamente seguro que permita a troca e de medições completas.
