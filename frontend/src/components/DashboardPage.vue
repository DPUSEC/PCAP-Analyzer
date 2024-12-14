<template>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200">
    <div class="dashboard" data-active-tab="uploads" v-if="is_authorized()">
        <div class="side-nav">
            <button v-on:click="active_tab = 'uploads'" :class="{ active: active_tab == 'uploads'}">
                <span class="material-symbols-rounded">upload</span>
                Uploads
            </button>
            <button v-on:click="active_tab = 'guides'" :class="{ active: active_tab == 'guides'}">
                <span class="material-symbols-rounded">developer_guide</span>
                Guides
            </button>
            <button v-on:click="active_tab = 'overview'" v-show="active_file != null" :class="{ active: active_tab == 'overview'}">
                <span class="material-symbols-rounded">overview</span>
                Overview
            </button>
            <button v-on:click="active_tab = 'dns'" v-show="active_file != null" :class="{ active: active_tab == 'dns'}">
                <span class="material-symbols-rounded">dns</span>
                DNS
            </button>
            <button v-on:click="active_tab = 'about'" :class="{ active: active_tab == 'about'}">
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
                    <div class="file" v-for="index in 5" :key="index"> <!-- Buradaki v-for, :key örnek olarak konulmuştur. -->
                        <div class="properties">test.pcap</div>
                        <div class="controls">
                            <button v-on:click="active_file = {}">Open</button>
                            <button>Download PCAP</button>
                            <button>Download Report</button>
                            <button><span class="material-symbols-rounded">delete</span></button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="tab guides" v-if="active_tab == 'guides'">Place here guides</div>
            <div class="tab dns" v-if="active_tab == 'overview'">
                Overview
            </div>
            <div class="tab dns" v-if="active_tab == 'dns'">
                DNS
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
    name: 'DashboardPage',
    methods: {
        upload_file: function (){
            var file_uploader = document.createElement("input");
            file_uploader.type = "file";
            file_uploader.click();
            file_uploader.onchange = async () => {
                let form_data = new FormData();
                let file_reader = new FileReader();
                const the_file = file_uploader.files[0];
                file_reader.onload = async (file_read_event) => {
                    const file_content = file_read_event.target.result;
                    form_data.append("scanName", the_file.name);
                    form_data.append("file", new Blob([file_content]), the_file.name);
                    try {
                        const response = await fetch("http://localhost:8000/api/v1/analyze", {
                            method: "POST",
                            headers: {
                                "Content-Type": "multipart/form-data",
                                "Authorization": localStorage.getItem("token")
                            },
                            body: form_data
                        });
                        console.warn(response);
                    } catch(error) {
                        console.error(error);
                    }
                    file_uploader.remove();
                };
                file_reader.readAsArrayBuffer(the_file);
            };
            file_uploader.oncancel = () => {
                file_uploader.remove();
            };
        },
        is_authorized: function () {
            if(localStorage.getItem("token") == null){
                this.$router.push("/login");
            } else {
                return true;
            }
        }
    },
    data() {
        return {
            active_tab: "uploads",
            active_file: null
        }
    }
}
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

            &:not(:last-child){
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
