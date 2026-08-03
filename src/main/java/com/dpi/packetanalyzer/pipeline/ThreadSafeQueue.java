package com.dpi.packetanalyzer.pipeline;

import java.util.LinkedList;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Bounded thread-safe queue used to pass packets between pipeline stages
 * (reader -> LB -> FP). Mirrors DPI::ThreadSafeQueue&lt;T&gt; from
 * thread_safe_queue.h, including its shutdown-wakes-everyone semantics
 * (which java.util.concurrent.BlockingQueue doesn't provide out of the box).
 */
public class ThreadSafeQueue<T> {

    private final LinkedList<T> queue = new LinkedList<>();
    private final int maxSize;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Condition notFull = lock.newCondition();
    private volatile boolean shutdown = false;

    public ThreadSafeQueue() {
        this(10_000);
    }

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    /** Pushes an item, blocking while the queue is full. No-op if shut down. */
    public void push(T item) {
        lock.lock();
        try {
            while (queue.size() >= maxSize && !shutdown) {
                notFull.awaitUninterruptibly();
            }
            if (shutdown) return;

            queue.addLast(item);
            notEmpty.signal();
        } finally {
            lock.unlock();
        }
    }

    /** Attempts to push without blocking. Returns false if full or shut down. */
    public boolean tryPush(T item) {
        lock.lock();
        try {
            if (queue.size() >= maxSize || shutdown) {
                return false;
            }
            queue.addLast(item);
            notEmpty.signal();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /** Pops an item, blocking while the queue is empty. Empty result on shutdown. */
    public Optional<T> pop() {
        lock.lock();
        try {
            while (queue.isEmpty() && !shutdown) {
                notEmpty.awaitUninterruptibly();
            }
            if (queue.isEmpty()) return Optional.empty();

            T item = queue.removeFirst();
            notFull.signal();
            return Optional.of(item);
        } finally {
            lock.unlock();
        }
    }

    /** Pops with a timeout. Empty result on timeout, empty queue, or shutdown. */
    public Optional<T> popWithTimeout(long timeoutMillis) {
        lock.lock();
        try {
            long nanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
            while (queue.isEmpty() && !shutdown) {
                if (nanos <= 0L) {
                    return Optional.empty();
                }
                try {
                    nanos = notEmpty.awaitNanos(nanos);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Optional.empty();
                }
            }
            if (queue.isEmpty()) return Optional.empty();

            T item = queue.removeFirst();
            notFull.signal();
            return Optional.of(item);
        } finally {
            lock.unlock();
        }
    }

    public boolean isEmpty() {
        lock.lock();
        try {
            return queue.isEmpty();
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return queue.size();
        } finally {
            lock.unlock();
        }
    }

    /** Signals shutdown, waking every thread blocked in push()/pop(). */
    public void shutdown() {
        lock.lock();
        try {
            shutdown = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public boolean isShutdown() {
        return shutdown;
    }
}
