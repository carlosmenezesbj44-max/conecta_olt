import os
import sys

# Adiciona o diretório do projeto ao sys.path para que os módulos internos sejam encontrados
path = '/home/carlosviptelecom/conecta_olt'
if path not in sys.path:
    sys.path.insert(0, path)

# Inicializa o banco de dados antes de carregar as rotas
from backend import db
db.init_db()

# NOTA: O PollingScheduler não deve ser iniciado aqui no PythonAnywhere
# pois as instâncias do Web App são efêmeras e podem rodar em múltiplos processos.
# O agendamento de coletas deve ser feito via "Tasks" no painel do PythonAnywhere.


# Como o projeto usa http.server, precisamos de um adaptador WSGI ou refatorar para Flask.
# Para PythonAnywhere, a forma recomendada é exportar um objeto chamado 'application'.

from backend.server import AppHandler
from wsgiref.handlers import SimpleHandler
from io import BytesIO

def application(environ, start_response):
    """
    Adaptador WSGI básico para usar o AppHandler existente do projeto.
    Nota: Em produção, recomenda-se usar um framework como Flask ou Django.
    """
    # Prepara o ambiente para simular uma requisição http.server
    stdin = environ['wsgi.input']
    stdout = BytesIO()
    stderr = environ['wsgi.errors']
    
    # Cria uma instância do handler simulando um socket de servidor
    class MockSocket:
        def __init__(self, output):
            self.output = output
        def makefile(self, mode, *args, **kwargs):
            if 'r' in mode: return stdin
            return self.output
        def sendall(self, b):
            self.output.write(b)
        def getsockname(self):
            return ('127.0.0.1', 80)

    handler = AppHandler(MockSocket(stdout), environ['REMOTE_ADDR'], None)
    
    # Mapeia o ambiente WSGI para os campos do BaseHTTPRequestHandler
    handler.command = environ['REQUEST_METHOD']
    handler.path = environ['PATH_INFO']
    if environ.get('QUERY_STRING'):
        handler.path += '?' + environ['QUERY_STRING']
    handler.request_version = environ['SERVER_PROTOCOL']
    handler.headers = {k.replace('HTTP_', '').replace('_', '-').title(): v for k, v in environ.items() if k.startswith('HTTP_')}
    if 'CONTENT_TYPE' in environ: handler.headers['Content-Type'] = environ['CONTENT_TYPE']
    if 'CONTENT_LENGTH' in environ: handler.headers['Content-Length'] = environ['CONTENT_LENGTH']
    
    # Adiciona requestline para evitar erro no log_request do BaseHTTPRequestHandler
    handler.requestline = f"{handler.command} {handler.path} {handler.request_version}"

    # Executa o método correspondente (do_GET, do_POST, etc)
    method_name = f'do_{handler.command}'
    if hasattr(handler, method_name):
        getattr(handler, method_name)()
    else:
        start_response('501 Not Implemented', [('Content-Type', 'text/plain')])
        return [b'Method not implemented']

    # Extrai o status e headers capturados pelo handler
    # Como o BaseHTTPRequestHandler escreve direto no wfile, precisamos capturar o que ele enviou
    stdout.seek(0)
    response_data = stdout.read()
    
    # Separa headers do corpo (o BaseHTTPRequestHandler envia a linha de status + headers + corpo)
    # Este adaptador é simplificado e pode precisar de ajustes dependendo da complexidade do handler.
    try:
        header_end = response_data.find(b'\r\n\r\n')
        if header_end != -1:
            header_part = response_data[:header_end].decode('utf-8')
            body = response_data[header_end+4:]
            
            lines = header_part.split('\r\n')
            status_line = lines[0] # HTTP/1.0 200 OK
            status_code = status_line.split(' ', 1)[1]
            
            headers = []
            for line in lines[1:]:
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    headers.append((k, v))
            
            start_response(status_code, headers)
            return [body]
    except Exception:
        pass

    start_response('200 OK', [('Content-Type', 'application/json')])
    return [response_data]
