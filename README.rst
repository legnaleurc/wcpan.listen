wcpan.listen
============


.. code:: python

    from tornado.httpserver import HTTPServer
    from tornado.ioloop import IOLoop
    from tornado.web import Application

    from wcpan.listen import create_sockets


    main_loop = IOLoop.instance()
    application = Application()
    server = HTTPServer(application)
    listen_options = [
        '8000',
        '127.0.0.1:8080',
        '/tmp/unix.socket',
    ]
    with create_sockets(listen_options) as sockets:
        server.add_sockets(sockets)
        main_loop.start()
        main_loop.close()
