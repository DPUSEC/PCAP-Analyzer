export default function AboutPage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-orange-50 to-white py-12">
      <div className="max-w-4xl mx-auto px-4">
        <div className="bg-white rounded-2xl shadow-lg p-8 md:p-12">
          <h1 className="text-3xl font-bold text-orange-600 mb-8">About DPUSEC PCAP Analyzer</h1>
          
          <div className="space-y-6 text-gray-700">
            <div className="prose max-w-none">
              <h2 className="text-xl font-semibold text-orange-500">System Details</h2>
              <ul className="list-disc pl-6 mt-2">
                <li>Flexible detection mechanism with customizable rules</li>
                <li>Multiple rule set support</li>
                <li>Detailed reporting and history tracking</li>
                <li>Cloud-based scalable infrastructure</li>
              </ul>
            </div>

            <div className="prose max-w-none">
              <h2 className="text-xl font-semibold text-orange-500">Technical Details</h2>
              <p className="mt-2">
              Our system consists of a high-performance background service developed in Go and a modern user interface based on Next.js. We use a customized version of Suricata as the analysis engine.
              </p>
            </div>

            <div className="mt-8 border-t pt-8">
              <h3 className="text-lg font-semibold text-orange-500">Contact</h3>
              <p className="mt-2">
                <strong>DPUSEC AR-GE Team</strong><br/>
                Dumlupınar University Merkez/Kütahya<br/>
                E-posta: <a href="mailto:iletisim@dpusec.org" className="text-orange-600 hover:underline">iletisim@dpusec.org</a><br/>
              </p>
            </div>

            <div className="mt-8 border-t pt-8">
              <h3 className="text-lg font-semibold text-orange-500">Developers</h3>
              <p className="mt-2">
                <strong>DPUSEC AR-GE Team</strong><br/>
                <ul>
                  <li><a href="https://linkedin.com/in/barisazar">Barış Azar</a></li>
                  <li><a href="https://linkedin.com/in/durmazdev" target="_blank">Abdullah Ahmet Durmaz</a></li>
                  <li><a href="https://linkedin.com/in/aliumutsoran" target="_blank">Ali Umut Soran</a></li>
                  <li><a href="https://linkedin.com/in/salihdoğanbülbül" target="_blank">Salih Doğan Bülbül</a></li>
                  <li><a href="https://www.linkedin.com/in/yusufcannc/" target="_blank">Yusuf Can Çakır</a></li>
                </ul>
              </p>
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}

