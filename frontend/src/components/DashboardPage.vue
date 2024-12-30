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
        overview
      </button>
      <button
        v-on:click="active_tab = 'credentials'"
        v-show="results != null"
        :class="{ active: active_tab == 'credentials' }"
      >
        <span class="material-symbols-rounded">dns</span>
        Credentials
      </button>
      <button
        v-on:click="active_tab = 'dns'"
        v-show="results != null"
        :class="{ active: active_tab == 'dns' }"
      >
        <span class="material-symbols-rounded">dns</span>
        DNS
      </button>
      <button
        v-on:click="active_tab = 'file_transfer'"
        v-show="results != null"
        :class="{ active: active_tab == 'file_transfer' }"
      >
        <span class="material-symbols-rounded">dns</span>
        File Transfer
      </button>
      <button
        v-on:click="active_tab = 'http'"
        v-show="results != null"
        :class="{ active: active_tab == 'http' }"
      >
        <span class="material-symbols-rounded">dns</span>
        HTTP
      </button>
      <button
        v-on:click="active_tab = 'ip_req'"
        v-show="results != null"
        :class="{ active: active_tab == 'ip_req' }"
      >
        <span class="material-symbols-rounded">dns</span>
        IP Requests
      </button>
      <button
        v-on:click="active_tab = 'http_ip'"
        v-show="results != null"
        :class="{ active: active_tab == 'http_ip' }"
      >
        <span class="material-symbols-rounded">dns</span>
        HTTP Reqs by IP
      </button>
      <button
        v-on:click="active_tab = 'port_scan'"
        v-show="results != null"
        :class="{ active: active_tab == 'port_scan' }"
      >
        <span class="material-symbols-rounded">dns</span>
        Port Scan Detection
      </button>
      <button
        v-on:click="active_tab = 'port_stats'"
        v-show="results != null"
        :class="{ active: active_tab == 'port_stats' }"
      >
        <span class="material-symbols-rounded">dns</span>
        Port Stats
      </button>
      <button
        v-on:click="active_tab = 'rce'"
        v-show="results != null"
        :class="{ active: active_tab == 'rce' }"
      >
        <span class="material-symbols-rounded">dns</span>
        RCE
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
              <button v-on:click="upload_file_by_id(file.ID)">Load</button>
              <button>Download</button>
              <button>
                <span class="material-symbols-rounded">delete</span>
              </button>
            </div>
          </div>
        </div>
      </div>
      <div class="tab guides" v-if="active_tab == 'guides'">
        Place here guides
      </div>
      <div class="tab overview" v-if="active_tab == 'overview'"></div>
      <div class="tab dns" v-if="active_tab == 'dns'">DNS</div>
      <div class="tab credentials" v-if="active_tab == 'credentials'">
        <div class="credentials">
          <div
            v-for="(credential, index) in results?.Credentials ?? []"
            :key="index"
          >
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ credential.PacketID }}</span>
                <span>{{ credential.SrcIP }}</span>
                <span>{{ credential.SrcPort }}</span>
                <span>{{ credential.DstIP }}</span>
                <span>{{ credential.DstPort }}</span>
                <span>{{ credential.FileName }}</span>
                <span>{{ credential.Arg }}</span>
                <span>{{ credential.Command }}</span>
                <span>{{ credential.MatchedKeyword }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab http_ip" v-if="active_tab == 'http_ip'">
        <div class="http_ip">
          <div
            v-for="(req, index) in results?.HttpRequestsByIP ?? []"
            :key="index"
          >
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ req.SourceIP }}</span>
                <span>{{ req.TotalRequestCount }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab ip_req" v-if="active_tab == 'ip_req'">
        <div class="ip_req">
          <div v-for="(req, index) in results?.IpRequest ?? []" :key="index">
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ req.IP }}</span>
                <span>{{ req.Count }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab http" v-if="active_tab == 'http'">
        <div class="http">
          <div v-for="(req, index) in results?.HttpRequests ?? []" :key="index">
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ req.Path }}</span>
                <span>{{ req.RequestCount }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab file_transfer" v-if="active_tab == 'file_transfer'">
        <div class="file_transfer">
          <div
            v-for="(file, index) in results?.FileTransfer ?? []"
            :key="index"
          >
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ file.PacketID }}</span>
                <span>{{ file.SrcIP }}</span>
                <span>{{ file.SrcPort }}</span>
                <span>{{ file.DstIP }}</span>
                <span>{{ file.DstPort }}</span>
                <span>{{ file.FileName }}</span>
                <span>{{ file.Arg }}</span>
                <span>{{ file.Command }}</span>
                <span>{{ file.MatchedKeyword }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab port_scan" v-if="active_tab == 'port_scan'">
        <div class="port_scan">
          <div
            v-for="(file, index) in results?.PortScanDetection ?? []"
            :key="index"
          >
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ file.IP }}</span>
                <span>{{ file.Ports }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab port_stats" v-if="active_tab == 'port_stats'">
        <div class="port_stats">
          <div v-for="(file, index) in results?.PortStats ?? []" :key="index">
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ file.Port }}</span>
                <span>{{ file.Requests }}</span>
                <span>{{ file.Responses }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab rce" v-if="active_tab == 'rce'">
        <div class="rce">
          <div v-for="(rce, index) in results?.RCE ?? []" :key="index">
            <ul>
              <li style="display: flex; justify-content: space-between">
                <span>{{ rce.PacketID }}</span>
                <span>{{ rce.SrcIP }}</span>
                <span>{{ rce.SrcPort }}</span>
                <span>{{ rce.DstIP }}</span>
                <span>{{ rce.DstPort }}</span>
                <span>{{ rce.FileName }}</span>
                <span>{{ rce.Arg }}</span>
                <span>{{ rce.Command }}</span>
                <span>{{ rce.MatchedKeyword }}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <div class="tab dns" v-if="active_tab == 'about'">
        <ul>
          <h1>We're DPUSEC</h1>
        </ul>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "DashboardPage",
  methods: {
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
          console.warn(data);
          this.results = data.Results;
          this.active_tab = "overview";
        } catch (error) {
          console.error(error);
        }
      };
    },
    upload_file_by_id: async function (id) {
      if (id == null) return console.warn("ID cannot be null");
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
        console.warn(data);
        this.results = data.Results;
        this.active_tab = "overview";
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
            console.warn(data.Analysis);
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
</style>
