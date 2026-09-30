import os
worker_class = 'uvicorn.workers.UvicornWorker'
workers = 1
bind = '0.0.0.0:' + os.environ.get('PORT', '10000')
accesslog = '-'
# Never include query strings, stream tokens, or credentials in access logs.
access_log_format = '%(h)s %(s)s %(b)s %(D)s'
timeout = 120
