/* ── WebSocket 聊天 ── */

document.addEventListener('alpine:init', () => {
  Alpine.data('chatApp', () => ({
    messages: [],
    typing: false,
    ws: null,
    counter: 0,

    connect() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = protocol + '//' + location.host + '/ws/chat';
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.scrollBottom();
      };

      this.ws.onmessage = (event) => {
        this.typing = false;
        try {
          const msg = JSON.parse(event.data);
          this.addMessage(msg.role, msg.content);
        } catch(e) {
          this.addMessage('agent', event.data);
        }
        this.scrollBottom();
      };

      this.ws.onclose = () => {
        this.addMessage('agent', '⚠️ 连接已断开。刷新页面重新连接。');
      };

      this.ws.onerror = () => {
        // Add welcome message even without WS
      };
    },

    addMessage(role, content) {
      this.counter++;
      const now = new Date();
      const time = now.getHours().toString().padStart(2, '0') + ':' +
                   now.getMinutes().toString().padStart(2, '0');
      this.messages.push({
        id: this.counter,
        role: role,
        content: content,
        time: time,
      });
      // Max 200 messages
      if (this.messages.length > 200) {
        this.messages = this.messages.slice(-200);
      }
    },

    send(text) {
      if (!text || !text.trim()) return;
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ content: text }));
        this.typing = true;
      } else {
        // Fallback: use fetch
        this.addMessage('user', text);
        this.typing = true;
        fetch('/api/tasks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ json_mode: '1', json_data: text })
        }).then(r => r.json()).then(data => {
          this.typing = false;
          if (data.task_id) {
            this.addMessage('agent', '✅ 任务已创建: `' + data.task_id + '`\n\n[查看进度](/finding/' + data.task_id + ')');
          }
        }).catch(e => {
          this.typing = false;
          this.addMessage('agent', '❌ 发送失败: ' + e.message);
        });
      }
    },

    quickAction(action) {
      const actions = {
        'help': '帮助',
        'status': '查看任务进度',
        'demo': '{"finding_id":"F-DEMO-001","vulnerability_type":"SQL Injection","severity":"high","affected_file":"src/api/search.py","affected_function":"search_users","line":42,"evidence":"用户输入通过字符串拼接进入 SQL 查询","scanner":"SAST"}',
      };
      const text = actions[action] || action;
      const input = this.$refs.input;
      input.value = text;
      input.focus();
      if (action === 'status' || action === 'help') {
        this.send(text);
        input.value = '';
      }
    },

    renderMarkdown(content) {
      if (!content) return '';
      if (window.marked) {
        return window.marked.parse(content);
      }
      // Simple fallback
      return content
        .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>');
    },

    scrollBottom() {
      this.$nextTick(() => {
        const el = this.$refs.messages;
        if (el) el.scrollTop = el.scrollHeight;
      });
    }
  }));
});
