/* ── 任务进度轮询 + 结果渲染 ── */

document.addEventListener('alpine:init', () => {
  Alpine.data('taskPoller', (taskId) => ({
    taskId: taskId,
    status: '',
    progress: '加载中...',
    stage: 0,
    loading: true,
    error: null,
    result: null,
    pollTimer: null,

    start() {
      this.poll();
    },

    async poll() {
      try {
        const resp = await fetch('/api/tasks/' + this.taskId);
        if (!resp.ok) { this.error = '任务不存在'; this.loading = false; return; }
        const data = await resp.json();
        this.status = data.status;
        this.progress = data.progress;
        this.stage = data.stage;

        if (data.status === 'succeeded' || data.status === 'failed') {
          this.loading = false;
          if (data.status === 'succeeded') {
            this.result = data.result;
            // Also load full result
            try {
              const fullResp = await fetch('/api/tasks/' + this.taskId + '/result');
              const full = await fullResp.json();
              if (full.ready && full.result) {
                this.result = full.result;
              }
            } catch(e) { /* ignore */ }
          }
          if (data.status === 'failed') {
            this.error = data.error || '修复失败';
            this.result = data.result;
          }
          if (this.pollTimer) clearInterval(this.pollTimer);
        } else {
          // Keep polling
          if (this.pollTimer) clearInterval(this.pollTimer);
          this.pollTimer = setInterval(() => this.poll(), 2000);
        }
      } catch(e) {
        this.error = e.message;
        this.loading = false;
      }
    },

    get statusText() {
      if (this.loading) return '⏳ 执行中...';
      if (this.status === 'succeeded') return '✅ 修复成功';
      if (this.status === 'failed') return '❌ 修复失败';
      return '⏳ ' + this.progress;
    },

    stageClass(n) {
      if (this.stage > n + 1) return 'done';
      if (this.stage === n + 1) return this.status === 'failed' ? 'failed' : 'active';
      return '';
    },

    renderResultSection(section) {
      if (!this.result || !this.result[section]) return '<p class=text-muted>无数据</p>';
      const data = this.result[section];
      return '<pre style="font-size:.8rem;white-space:pre-wrap;max-height:400px;overflow-y:auto;">' +
        JSON.stringify(data, null, 2).replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre>';
    },

    highlightDiff(content) {
      if (!content) return '';
      const code = content.replace(/</g, '&lt;').replace(/>/g, '&gt;');
      let html = '';
      const lines = code.split('\n');
      for (const line of lines) {
        if (line.startsWith('+++') || line.startsWith('---')) {
          html += '<span class="diff-hdr">' + line + '</span>\n';
        } else if (line.startsWith('+')) {
          html += '<span class="diff-add">' + line + '</span>\n';
        } else if (line.startsWith('-')) {
          html += '<span class="diff-del">' + line + '</span>\n';
        } else {
          html += line + '\n';
        }
      }
      return html;
    },

    // marked.js integration
    get marked() {
      return window.marked;
    }
  }));
});
