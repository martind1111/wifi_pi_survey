#ifndef _WORKER_H
#define _WORKER_H

class ApplicationContext;

class Worker {
public:
    Worker(ApplicationContext* ctx) : context(ctx) { }

    virtual void Run() = 0;

    ApplicationContext* GetMutableContext() { return context; }

    const ApplicationContext* GetContext() const { return context; }

private:
    ApplicationContext* context;
};

#endif // _WORKER_H
