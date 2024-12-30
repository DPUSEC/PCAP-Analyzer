<template>
  <link
    rel="stylesheet"
    href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200"
  />
  <div class="dashboard" data-active-tab="uploads" v-if="is_authorized()">
    <div class="side-nav">
      <button
        v-on:click="active_tab = 'uploads'"
        :class="{ active: active_tab == 'uploads' }"
      >
        <span class="material-symbols-rounded">upload</span>
        Uploads
      </button>
      <button
        v-on:click="active_tab = 'guides'"
        :class="{ active: active_tab == 'guides' }"
      >
        <span class="material-symbols-rounded">developer_guide</span>
        Guides
      </button>
      <button
        v-on:click="active_tab = 'overview'"
        v-show="results != null"
        :class="{ active: active_tab == 'overview' }"
      >
        <span class="material-symbols-rounded">overview</span>
        Overview
      </button>
      <button
        v-on:click="active_tab = 'credentials'"
        v-show="results != null"
        :class="{ active: active_tab == 'credentials' }"
      >
        <span class="material-symbols-rounded">key_vertical</span>
        Credentials
      </button>
      <button
        v-on:click="active_tab = 'file_transfer'"
        v-show="results != null"
        :class="{ active: active_tab == 'file_transfer' }"
      >
        <span class="material-symbols-rounded">scan</span>
        File Transfer
      </button>
      <button
        v-on:click="active_tab = 'http'"
        v-show="results != null"
        :class="{ active: active_tab == 'http' }"
      >
        <span class="material-symbols-rounded">http</span>
        HTTP
      </button>
      <button
        v-on:click="active_tab = 'ip_req'"
        v-show="results != null"
        :class="{ active: active_tab == 'ip_req' }"
      >
        <span class="material-symbols-rounded">host</span>
        IP Requests
      </button>
      <button
        v-on:click="active_tab = 'http_ip'"
        v-show="results != null"
        :class="{ active: active_tab == 'http_ip' }"
      >
        <span class="material-symbols-rounded">host</span>
        HTTP Reqs by IP
      </button>
      <button
        v-on:click="active_tab = 'port_scan'"
        v-show="results != null"
        :class="{ active: active_tab == 'port_scan' }"
      >
        <span class="material-symbols-rounded">radar</span>
        Port Scan Detection
      </button>
      <button
        v-on:click="active_tab = 'port_stats'"
        v-show="results != null"
        :class="{ active: active_tab == 'port_stats' }"
      >
        <span class="material-symbols-rounded">query_stats</span>
        Port Stats
      </button>
      <button
        v-on:click="active_tab = 'rce'"
        v-show="results != null"
        :class="{ active: active_tab == 'rce' }"
      >
        <span class="material-symbols-rounded">settings_remote</span>
        RCE
      </button>
      <button
        v-on:click="active_tab = 'xss'"
        v-show="results != null"
        :class="{ active: active_tab == 'xss' }"
      >
        <span class="material-symbols-rounded">frame_source</span>
        XSS
      </button>
      <button
        v-on:click="active_tab = 'about'"
        :class="{ active: active_tab == 'about' }"
      >
        <span class="material-symbols-rounded">info</span>
        About
      </button>
    </div>
    <div class="tabs">
      <div class="tab uploads" v-if="active_tab == 'uploads'">
        <div>
          <button v-on:click="upload_file()">
            <span class="material-symbols-rounded">upload_file</span>
            Upload New PCAP
          </button>
        </div>
        <div class="uploaded-file-list">
          <div
            class="file"
            v-for="(file, index) in uploaded_files"
            :key="index"
          >
            <!-- Buradaki v-for, :key örnek olarak konulmuştur. -->
            <div class="properties">{{ file.FileName }}</div>
            <div class="controls">
              <button v-on:click="upload_file_by_id(file.ID)">
                <span class="material-symbols-rounded">file_open</span>
              </button>
              <button v-on:click="download_file_by_id(file.ID, file.FileName)">
                <span class="material-symbols-rounded">download</span>
              </button>
              <button v-on:click="delete_file_by_id(file.ID)">
                <span class="material-symbols-rounded">delete</span>
              </button>
            </div>
          </div>
        </div>
      </div>
      <div class="tab guides" v-if="active_tab == 'guides'">
        Place here guides
      </div>
      <div class="tab overview" v-if="active_tab == 'overview'">
        <h2>Overview</h2>
        <div>Credentials
            <div>{{results?.CredentialsResults?.length??0}}</div>
            <ul style="display: flex; gap: 20px;">
                <li v-for="(credential, index) in get_importants_from_object(results?.CredentialsResults?.reduce((a,b)=>{a[b.Arg] = (a[b.Arg]??0)+1; return a;}, {}), 3)??[]" :key="index">{{credential}}</li>
            </ul>
        </div>
        <div>File Transfer
            <div>{{results?.FileTransferResults?.length??0}}</div>
        </div>
        <div>HTTP
            <div>{{results?.HttpReqResults?.length??0}}</div>
        </div>
        <div>IP Requests
            <div>{{results?.IpRequestResults?.length??0}}</div>
            <ul style="display: flex; gap: 20px;">
                <li v-for="(ip, index) in get_importants_from_object(results?.IpRequestResults?.reduce((a,b)=>{a[b.IP]=b.Count;return a;},{}), 3)??[]" :key="index">{{ip}}</li>
            </ul>
        </div>
        <div>HTTP Reqs by IP
            <div>{{results?.HttpReqIPsResults?.length??0}}</div>
            <ul style="display: flex; gap: 20px;">
                <li v-for="(ip, index) in get_importants_from_object(results?.HttpReqIPsResults?.reduce((a,b)=>{a[b.SourceIP]=b.TotalRequestCount;return a;},{}), 3)??[]" :key="index">{{ip}}</li>
            </ul>
        </div>
        <div>Port Scan Results
            <div>{{results?.PortScanDetectionResults?.length??0}}</div>
        </div>
        <div>Port Stats
            <div>{{results?.PortStatResults?.length??0}}</div>
            <ul style="display: flex; gap: 20px;">
                <li v-for="(ip, index) in get_importants_from_object(results?.PortStatResults?.reduce((a,b)=>{a[b.Port]=b.Requests+b.Responses;return a;},{}), 3)??[]" :key="index">{{ip}}</li>
            </ul>
        </div>
        <div>RCE
            <div>{{results?.RceResults?.length??0}}</div>
        </div>
        <div>XSS
            <div>{{results?.XssResults?.length??0}}</div>
        </div>
      </div>
      <div class="tab credentials" v-if="active_tab == 'credentials'">
        <div class="credentials">
            <table>
              <tr v-for="(credential, index) in results?.CredentialsResults ?? []"
              :key="index">
                <td>{{ credential.PacketID }}</td>
                <td>{{ credential.SrcIP }}</td>
                <td>{{ credential.SrcPort }}</td>
                <td>{{ credential.DstIP }}</td>
                <td>{{ credential.DstPort }}</td>
                <td>{{ credential.FileName }}</td>
                <td>{{ credential.Arg }}</td>
                <td>{{ credential.Command }}</td>
                <td>{{ credential.MatchedKeyword }}</td>
              </tr>
        </table>
        </div>
      </div>
      <div class="tab http_ip" v-if="active_tab == 'http_ip'">
          <div class="http_ip">
            <table>
              <tr
              v-for="(req, index) in results?.HttpReqIPsResults ?? []"
              :key="index">
                <td>{{ req.SourceIP }}</td>
                <td>{{ req.TotalRequestCount }}</td>
              </tr>
        </table>
        </div>
      </div>
      <div class="tab xss" v-if="active_tab == 'xss'">
          <div class="xss">
            <table>
              <tr
              v-for="(req, index) in results?.XssResults ?? []"
              :key="index"
            >
                <td>{{ req.PacketID }}</td>
                <td>{{ req.SrcIP }}</td>
                <td>{{ req.SrcPort }}</td>
                <td>{{ req.DstIP }}</td>
                <td>{{ req.DstPort }}</td>
                <td>{{ req.FileName }}</td>
                <td>{{ req.Arg }}</td>
                <td>{{ req.Command }}</td>
                <td>{{ req.MatchedKeyword }}</td>
              </tr>
        </table>
        </div>
      </div>
      <div class="tab ip_req" v-if="active_tab == 'ip_req'">
          <div class="ip_req">
            <table>
              <tr v-for="(req, index) in results?.IpRequestResults ?? []" :key="index">
                <td>{{ req.IP }}</td>
                <td>{{ req.Count }}</td>
              </tr>
            </table>
        </div>
      </div>
      <div class="tab http" v-if="active_tab == 'http'">
        <div class="http">
            <table>
              <tr v-for="(req, index) in results?.HttpReqResults ?? []" :key="index">
                <td>{{ req.Path }}</td>
                <td>{{ req.RequestCount }}</td>
              </tr>
        </table>
        </div>
      </div>
      <div class="tab file_transfer" v-if="active_tab == 'file_transfer'">
        <div class="file_transfer">
            <table>
              <tr
              v-for="(file, index) in results?.FileTransferResults ?? []"
              :key="index"
            >
                <td>{{ file.PacketID }}</td>
                <td>{{ file.SrcIP }}</td>
                <td>{{ file.SrcPort }}</td>
                <td>{{ file.DstIP }}</td>
                <td>{{ file.DstPort }}</td>
                <td>{{ file.FileName }}</td>
                <td>{{ file.Arg }}</td>
                <td>{{ file.Command }}</td>
                <td>{{ file.MatchedKeyword }}</td>
              </tr>
        </table>
        </div>
      </div>
      <div class="tab port_scan" v-if="active_tab == 'port_scan'">
        <div class="port_scan">
            <table>
              <tr
              v-for="(file, index) in results?.PortScanDetectionResults ?? []"
              :key="index"
            >
                <td>{{ file.IP }}</td>
                <td>{{ file.Ports }}</td>
              </tr>
        </table>
        </div>
      </div>
      <div class="tab port_stats" v-if="active_tab == 'port_stats'">
        <div class="port_stats">
            <table>
              <tr v-for="(file, index) in results?.PortStatResults ?? []" :key="index">
                <td>{{ file.Port }}</td>
                <td>{{ file.Requests }}</td>
                <td>{{ file.Responses }}</td>
              </tr>
            </table>
        </div>
      </div>
      <div class="tab rce" v-if="active_tab == 'rce'">
        <div class="rce">
            <table>
              <tr v-for="(rce, index) in results?.RceResults ?? []" :key="index">
                <td>{{ rce.PacketID }}</td>
                <td>{{ rce.SrcIP }}</td>
                <td>{{ rce.SrcPort }}</td>
                <td>{{ rce.DstIP }}</td>
                <td>{{ rce.DstPort }}</td>
                <td>{{ rce.FileName }}</td>
                <td>{{ rce.Arg }}</td>
                <td>{{ rce.Command }}</td>
                <td>{{ rce.MatchedKeyword }}</td>
              </tr>
        </table>
        </div>
      </div>
      <div class="tab about" v-if="active_tab == 'about'">
        <h1>We're DPUSEC</h1>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "DashboardPage",
  methods: {
    get_importants_from_object: (obj, num=3) => {
        if(!obj) return null;
        return Object.keys(obj).sort((a, b) => obj[b] - obj[a]).slice(0, Math.min(num, Object.keys(obj).length));
    },
    upload_file: function () {
      var file_uploader = document.createElement("input");
      file_uploader.type = "file";
      file_uploader.click();
      file_uploader.onchange = async () => {
        let form_data = new FormData();
        const the_file = file_uploader.files[0];
        form_data.append("scanName", the_file.name);
        form_data.append("file", the_file);
        try {
          const response = await fetch(
            "http://localhost:8000/api/v1/analysis",
            {
              method: "POST",
              headers: {
                Authorization: "Bearer " + localStorage.getItem("token"),
              },
              body: form_data,
            }
          );
          let data = await response.json();
          this.results = data.Results;
          this.active_tab = "overview";
          this.reload_file_list();
        } catch (error) {
          console.error(error);
        }
      };
    },
    reload_file_list: async function () {
        const response = await fetch(
            "http://localhost:8000/api/v1/analysis",
            {
            method: "GET",
            headers: {
                Authorization: "Bearer " + localStorage.getItem("token"),
            },
            }
        );
        if (response.status == 401) this.$router.push("/login");
        const data = await response.json();
        this.uploaded_files = data.Analysis;
    },
    upload_file_by_id: async function (id) {
      if (id == null) return console.error("ID cannot be null");
      try {
        const response = await fetch(
          `http://localhost:8000/api/v1/analysis/${id}`,
          {
            method: "GET",
            headers: {
              Authorization: "Bearer " + localStorage.getItem("token"),
            },
          }
        );
        let data = await response.json();
        this.results = data.Analysis;
        this.active_tab = "overview";
        this.reload_file_list();
      } catch (error) {
        console.error(error);
      }
    },
    delete_file_by_id: async function (id) {
      if (id == null) return console.error("ID cannot be null");
      try {
        await fetch(
          `http://localhost:8000/api/v1/analysis/${id}`,
          {
            method: "DELETE",
            headers: {
              Authorization: "Bearer " + localStorage.getItem("token"),
            },
          }
        );
        await this.reload_file_list();
      } catch (error) {
        console.error(error);
      }
    },
    download_file_by_id: async function (id, file_name = "download.pcap") {
      if (id == null) return console.error("ID cannot be null");
      try {
        const response = await fetch(
          `http://localhost:8000/api/v1/analysis/${id}/download`,
          {
            method: "GET",
            headers: {
              Authorization: "Bearer " + localStorage.getItem("token"),
            },
          }
        );
        let blob = await response.blob();
        let file = new File([blob], file_name, { type: blob.type });
        let uri = await URL.createObjectURL(file);
        window.open(uri, "target=_blank");
        await URL.revokeObjectURL(uri);
      } catch (error) {
        console.error(error);
      }
    },
    is_authorized: async function () {
      if (localStorage.getItem("token") == null) {
        this.$router.push("/login");
      } else {
        if (!this.is_authorized_runned) {
          this.is_authorized_runned = true;
          try {
            await this.reload_file_list();
          } catch (err) {
            this.$router.push("/login");
          }
        }
        return true;
      }
    },
  },
  data() {
    return {
      active_tab: "uploads",
      results: null,
      uploaded_files: [],
      is_authorized_runned: false,
    };
  },
};
</script>

<style scoped>
button {
  padding: 4px;
  background: darkorange;
  border: none;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 5px;

  &:hover {
    background: orange;
  }
}

.dashboard {
  width: 100%;
  display: flex;
  flex-direction: row;
  & > * {
    padding: 4px;
    box-sizing: border-box;
  }

  & .side-nav {
    width: 200px;
    gap: 5px;
    display: flex;
    flex-direction: column;

    & button {
      justify-content: flex-start;

      &.active {
        border-left: 4px solid color-mix(in srgb, orange, white);
      }
    }
  }

  & .tabs {
    flex-grow: 1;

    & .tab {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
  }
}

.uploads {
  & .uploaded-file-list {
    border-radius: 4px;
    border: 2px solid #0004;

    & .file {
      display: flex;
      flex-direction: row;
      justify-content: space-between;
      padding: 2px;
      align-items: center;

      &:not(:last-child) {
        border-bottom: 1px solid #0004;
      }

      & .controls {
        display: flex;
        gap: 5px;
      }
    }
  }
}

table {
    border-radius: 8px;
    border: 1px solid black;
    padding: 8px;
    width: 100%;

    & td {
        border-bottom: 1px solid #0004;
    }
}
</style>
