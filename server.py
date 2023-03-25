import socketcore

if __name__ == '__main__':
    server = socketcore.Server("127.0.0.1",5000)
    server.start()