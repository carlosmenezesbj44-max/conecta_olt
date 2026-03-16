# ConectaOLT

Aplicacao web local e leve para gerencia de OLTs multi-marca com foco em:

- inventario de OLTs, placas e portas GPON
- cadastro de ONU com nome do cliente, bairro e cidade
- exibicao de sinal, trafego, temperatura e VLAN por ONU
- fila exclusiva de solicitacoes de liberacao
- deteccao de ONU ja cadastrada para acionar move entre portas
- alertas de lotacao por porta
- graficos simples de consumo e distribuicao de sinal

## Como executar

```powershell
python main.py
```

Depois acesse `http://127.0.0.1:8080`.

## O que esta fase entrega

- backend HTTP usando apenas biblioteca padrao do Python
- banco SQLite local criado automaticamente em `conectaolt.db`
- inicializacao limpa, sem dados demo automaticos
- endpoints JSON para dashboard, OLTs, ONUs, profiles e solicitacoes
- acao de autorizar nova ONU
- acao de mover ONU quando o serial ja existe em outra porta
- historico persistido de OLT, portas e ONUs
- configuracao de conexao por OLT
- scheduler de polling automatico
- polling manual por OLT ou geral
- protocolos de coleta `mock`, `json-file`, `command` e `api`

## Estrutura

- `main.py`: ponto de entrada
- `backend/server.py`: servidor HTTP e rotas da API
- `backend/db.py`: schema e regras de negocio
- `backend/collectors/service.py`: orquestracao de coleta e protocolos
- `backend/poller.py`: scheduler automatico
- `backend/vendors.py`: catalogo de capacidades por marca
- `static/`: interface web
- `samples/normalized-payload.example.json`: exemplo de payload para integracao real

## Protocolos de coleta

### `mock`

Usa os dados atuais do banco para simular leituras reais e alimentar historico.

### `json-file`

Le um arquivo JSON local no formato normalizado do exemplo em `samples/normalized-payload.example.json`.

### `command`

Executa um comando local e espera JSON normalizado no `stdout`. Isso permite usar scripts externos por marca.

Exemplo:

```powershell
python scripts\collect_huawei.py --input-dir samples\huawei-cli
```

### `api`

Consulta um endpoint HTTP que retorne o mesmo JSON normalizado.

## Endpoints novos

- `GET /api/connections`
- `POST /api/connections/{olt_id}`
- `POST /api/olts/{olt_id}/poll`
- `GET /api/history/dashboard`
- `GET /api/onus/{onu_id}/history`
- `GET /api/events`

## Proximo passo recomendado

O proximo salto e implementar coletores reais por marca convertendo CLI/API da Huawei, ZTE e FiberHome para o payload normalizado. O contrato para isso ja esta pronto.

## Primeiro coletor real: Huawei

Foi incluido um parser inicial para Huawei em:

- `backend/collectors/huawei_cli.py`
- `scripts/collect_huawei.py`

Ele converte arquivos de saida CLI para o JSON normalizado da plataforma. O diretorio `samples/huawei-cli/` mostra o formato esperado de entradas:

- `olt.txt`
- `board.txt`
- `ont_summary.txt`
- `traffic.txt`
- `optical.txt`
- `service_port.txt`
- `autofind.txt`

Teste rapido:

```powershell
python scripts\collect_huawei.py --input-dir samples\huawei-cli
```

Coleta via SSH com chave:

```powershell
python scripts\collect_huawei.py --host 10.10.0.11 --username admin --key-path C:\chaves\olt_huawei.pem --save-dir .\debug-huawei
```

Para usar no sistema:

1. Abra a aba `Coleta`
2. Na OLT Huawei, escolha o protocolo `command`
3. Configure:

```powershell
python scripts\collect_huawei.py --input-dir samples\huawei-cli
```

4. Clique em `Executar poll`

Se quiser usar SSH direto pela aba `Coleta`, basta configurar o `command` com algo neste formato:

```powershell
python scripts\collect_huawei.py --host 10.10.0.11 --username admin --key-path C:\chaves\olt_huawei.pem
```

Limite atual: o modo SSH usa o cliente `ssh` do sistema e espera autenticacao por chave ou agente. Nao foi implementado login por senha interativa.

## Credenciais

Usuario e senha da OLT agora podem ser informados diretamente no cadastro/edicao da OLT.

No Windows, as senhas e tokens salvos no banco sao protegidos com DPAPI do proprio sistema operacional antes de serem gravados no SQLite. A aplicacao descriptografa esses valores somente em runtime quando precisa montar a conexao.
