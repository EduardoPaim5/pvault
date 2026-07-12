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
- clipboard X11/Wayland com TTL sem bloquear o terminal;
- troca de senha, rotação de recovery, backup, restore, doctor e shell;
- configuração XDG, man page e pacote Arch local.

Critério agora coberto por regressão PTY: um fluxo descartável executa `init`,
`add`, troca e rejeição da senha anterior, rotação e rejeição da recovery
anterior, `passwd --recovery`, backup, mutação e restore autenticado. O cenário
confirma o rollback esperado, a persistência dos registros, ausência de
segredos nas superfícies observáveis e permissões 0600/0700.

## Fase 3 — Estabilização para uso real (em andamento)

Infraestrutura entregue neste marco:

- scripts locais para GCC, Clang, ASan/UBSan, Release e instalação de teste;
- workflow hospedado opcional que chama os mesmos scripts locais;
- smoke fuzz limitado, seeds sintéticos e corpus persistente privado por target;
- fault injection determinística por etapa de commit, backup e restore, além de
  `open/write/fsync/rename/close`, com limpeza de resíduos e reabertura
  autenticada do snapshot esperado;
- testes com PTY controlador real para entrada oculta e restauração do terminal
  em `SIGINT/SIGHUP/SIGQUIT/SIGTERM/SIGTSTP`;
- testes determinísticos dos caminhos X11/Wayland do clipboard com owner falso,
  transporte por pipe, ambiente filtrado, TTL, `SIGPIPE` e morte abrupta do
  supervisor sem deixar owner órfão;
- harness opt-in em `Xvfb` descartável, exercitado com repetição, para validar
  round-trip, TTL e parent-death de `/usr/bin/xclip` real sem tocar no
  clipboard da sessão do usuário;
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
  pinning 0400 e falha conservadora antes de qualquer poda suspeita;
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
  parent-death.

Permanecem como gates da fase:

- auditoria independente do formato, parser, memória e processos;
- acrescentar cobertura equivalente para `wl-copy` em uma sessão Wayland
  descartável;
- ensaio manual separado do `xclip` dentro do i3, com confirmação explícita de
  que o clipboard ativo será substituído;
- CI em arquiteturas e libcs diferentes;
- campanhas longas de fuzzing, minimização e triagem privada dos artefatos;
- reprodução cruzada em duas máquinas e toolchains independentes;
- publicação efetiva de release assinada e checksum real no PKGBUILD;
- congelamento do formato v1.0 com vetores independentes e drill testado de
  rescue, rollback-copy e restore;
- repetição do restore drill em uma máquina separada.

O v1.0 é o primeiro e único formato implementado. Uma migração v1→v1 seria
apenas regravação e não satisfaria o contrato. A migração cross-version passa a
ser gate obrigatório da primeira release que escrever um vNext real, com
fixture N-1, política explícita para recovery e transformação sem perda.

Gate: não recomendar credenciais reais antes de corrigir achados da auditoria e
executar recuperação periódica de snapshots em uma máquina separada.

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
