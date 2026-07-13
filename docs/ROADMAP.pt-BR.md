# Roadmap do PVault

## Fase 1 — Fundação criptográfica e formato (concluída)

- formato v1.0 candidato, serializado explicitamente e documentado;
- Argon2id, VMK aleatória, dois keyslots e XChaCha20-Poly1305;
- arena segura, page locking, limpeza garantida e limites rígidos;
- CBOR determinístico, testes negativos e fuzzers;
- escrita atômica, locks, detecção de stale writer e backups.

Critério atingido: round-trip, adulteração, truncamento, senha/recovery erradas,
limites e serialização determinística passam em GCC, Clang, ASan e UBSan.

## Fase 2 — Produto desktop CLI (concluída em pre-alpha)

- `init`, `add`, `edit`, `remove`, `list`, `show` e `copy`;
- gerador de senha, picker ncurses e integração opcional com rofi;
- clipboard X11 nativo com TTL sem bloquear o terminal e recusa fail-closed de
  sessões Wayland, sem fallback XWayland;
- troca de senha, rotação de recovery, backup, restore, doctor e shell;
- configuração XDG, man page e pacote Arch local.

Critério agora coberto por regressão PTY: um fluxo descartável executa `init`,
`add`, troca e rejeição da senha anterior, rotação e rejeição da recovery
anterior, `passwd --recovery`, backup, mutação e restore autenticado. O cenário
confirma o rollback esperado, a persistência dos registros, ausência das chaves
e senhas sintéticas nas superfícies observadas e permissões 0600/0700. Isso não
equivale a auditoria nem torna o software adequado para credenciais reais.

## Fase 3 — Estabilização para uso real (em andamento; uso real ainda vetado)

Infraestrutura entregue neste marco:

- scripts locais para GCC, Clang, ASan/UBSan, Release e instalação de teste;
- perfil Clang LSan standalone em container isolado, com hardening do processo
  preservado, controle negativo obrigatório, logs por PID para workers
  destacados, contabilização test-only do allocator protegido da libsodium e
  rejeição de processos residuais;
- workflow hospedado opcional que chama os mesmos scripts locais;
- smoke fuzz limitado, seeds sintéticos e corpus persistente privado por target;
- fault injection determinística por etapa de commit, backup e restore, além de
  `open/write/fsync/rename/close`, com limpeza de resíduos e reabertura
  autenticada do snapshot esperado;
- testes com PTY controlador real para entrada oculta e restauração do terminal
  em `SIGINT/SIGHUP/SIGQUIT/SIGTERM/SIGTSTP`;
- testes determinísticos do caminho X11 e de targets Wayland experimentais não
  instaláveis, com owner falso, transporte por pipe, ambiente filtrado, TTL,
  `SIGPIPE` e morte abrupta do supervisor sem deixar owner órfão;
- harness opt-in em `Xvfb` descartável, exercitado com repetição, para validar
  round-trip, TTL e parent-death de `/usr/bin/xclip` real sem tocar no
  clipboard da sessão do usuário;
- harness de caracterização opt-in com Weston headless descartável e targets
  não instaláveis de `wl-copy`/`wl-paste`; o resultado verde reproduz retenção
  dos bytes sintéticos após saída do owner e clear, portanto não certifica
  suporte nem revogação. Destruir o compositor é cleanup do próprio harness;
- comparação automatizada de duas árvores de instalação Release independentes;
- procedimento documentado de release, assinatura, checksums e reprodução;
- contrato documentado para tratamento fail-closed, congelamento do v1.0,
  rollback e rescue; somente a futura migração cross-version ainda não possui
  implementação;
- abertura de snapshots via descritor validado, rejeição de symlink/hardlink e
  permissões inseguras;
- transações confinadas a um `dirfd` estável, publicação `no-replace` em `init`
  e backups, readback pós-commit e recusa de sobrescrever arquivo não-PVault em
  `restore`, incluindo recusa de troca implícita entre linhagens de cofre;
- retenção automática isolada por cofre, com AEAD/CBOR e geração autenticada,
  pinning 0400 e falha conservadora antes de qualquer poda suspeita; cada
  varredura abre uma descrição independente do diretório validado, sem
  reutilizar cursor compartilhado entre gerações;
- `rescue inspect/verify/recover` e rollback-copy separados do cofre ativo,
  com publicação 0400 no-replace, readback byte-exato e autenticação por senha
  ou recovery;
- restore drill local descartável com canários sintéticos, backup, mutação,
  rescue, verificação pelos dois keyslots e restore em caminho isolado.
- configuração aberta por descritor e validada quanto a owner, modo, links,
  tipo, parent, limites, NUL e duplicatas, com parsing transacional e testes
  contra symlink, hardlink, FIFO e arquivo superdimensionado.
- política única para novas senhas mestras, com piso de 16 bytes e rejeição de
  valores comuns, sequências e repetições óbvias; credenciais consumidas e
  zeradas logo após criação/unwrap, antes do I/O ou parse restante;
- ACK do clipboard após payload enfileirado, write-end fechado, owner observado
  vivo e timer suspend-aware armado com `CLOCK_BOOTTIME`, além da normalização
  de sinais herdados e regressões para owner morto antes/na metade da leitura e
  parent-death;
- gate compilado: o backend exige `WAYLAND_DISPLAY` vazio,
  `XDG_SESSION_TYPE=x11` e `DISPLAY` não vazio; metadados ausentes/desconhecidos
  falham fechados. `copy`/`pick --copy` aplicam o gate antes do unlock e
  `generate` antes da geração. O `shell` ainda abre para leitura, mas seu
  `copy` falha; a classificação confia no ambiente e não autentica o servidor;
- o owner/clear Wayland permanece apenas como experimento não instalável; sua
  retenção observada no Weston impede promovê-lo a funcionalidade do produto;
- `SIGCHLD` normalizado no início do CLI para que estado ignorado/bloqueado
  herdado não invalide wait/reap de subprocessos; helpers continuam a
  normalizar seu próprio estado;
- fault injection para colisão idempotente seguida de falha no `fsync`, com
  liberação incondicional do snapshot carregado e retry sem perda;
- contrato de CLI queryless para `edit`, `remove`, `show` e `copy`, com seleção
  pelo picker interno em vez de título, username, URL, tag ou ID persistente em
  `argv`;
- recusa de metadados em stdout não-TTY para `list`, `show`, `pick` sem cópia e
  `rescue verify`, salvo opt-in deliberado com `--allow-redirect`; `shell` exige
  stdin e stdout terminais;
- custom fields selecionados privadamente por índice com `--field custom`, status
  de `add`/`edit` sem ID e rofi opt-in limitado a título sanitizado, token
  efêmero e ambiente allowlisted.

Essa mudança de interface é uma quebra intencional de pre-alpha. As antigas
formas posicionais com `QUERY` falham explicitamente como erro de uso, em vez de
serem reinterpretadas ou manterem vazamento compatível. `--allow-redirect` não
é um selo de segurança: apenas registra que o operador escolheu conscientemente
um destino não-TTY e assume suas permissões, logs e retenção.

Permanecem como gates da fase:

- auditoria independente do formato, parser, memória e processos;
- redesenhar a integração Wayland antes de qualquer habilitação em produção; o
  experimento atual e seu teste verde não satisfazem cleanup ou revogação;
- execução humana de `scripts/test-live-x11-i3.sh` na sessão i3/X11 nativa,
  nunca pelo CI, com consentimento explícito para substituir o clipboard ativo;
  o ensaio usa apenas canário sintético, não lê, salva nem restaura o valor
  anterior e aborta ao detectar clipboard manager. O TTL encerra a posse da
  seleção pelo PVault, mas não prova revogação ou apagamento; este gate só fecha
  depois que uma pessoa executar e revisar o resultado;
- CI em arquiteturas e libcs diferentes;
- campanhas longas de fuzzing, minimização e triagem privada dos artefatos;
- reprodução cruzada em duas máquinas e toolchains independentes;
- publicação efetiva de release assinada e checksum real no PKGBUILD;
- congelamento do formato v1.0 com vetores independentes e drill testado de
  rescue, rollback-copy e restore;
- repetição do restore drill em uma máquina separada;
- auditoria independente do novo limite de metadados da CLI, incluindo
  redirecionamento explícito, picker externo e regressões contra argv, ambiente,
  stdout/stderr e logs.

O v1.0 é o primeiro e único formato implementado. Uma migração v1→v1 seria
apenas regravação e não satisfaria o contrato. A migração cross-version passa a
ser gate obrigatório da primeira release que escrever um vNext real, com
fixture N-1, política explícita para recovery e transformação sem perda.

Gate: não recomendar credenciais reais antes de corrigir achados da auditoria,
auditar independentemente o contrato queryless/TTY e executar recuperação
periódica de snapshots em uma máquina separada.

## Fase 4 — Android e sincronização (adiada)

1. separar interfaces Linux de memória/arquivo e portar os módulos
   criptográficos, modelo e fixtures para Android NDK;
2. criar app read-only com armazenamento protegido por Android Keystore;
3. parear transporte P2P e preservar toda cópia conflitante;
4. projetar merge por registro, identidade/revogação de dispositivos e defesa
   contra rollback/forks;
5. somente então habilitar escrita móvel e autofill.

Esta fase exige revisão própria do threat model. Biometria desbloqueia uma chave
protegida pelo sistema; ela não substitui a criptografia do cofre nem a recovery
key offline.
