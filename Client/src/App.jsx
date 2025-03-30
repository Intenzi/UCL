import { useState, useEffect } from "react"
import {
	BrowserRouter as Router,
	Routes,
	Route,
	useNavigate,
	useLocation,
} from "react-router-dom"
import "./App.css"
import img1 from "./assets/pythonn.png"
import img2 from "./assets/java2.svg"
import img3 from "./assets/js.png"

// -------- Home Page Component --------
function HomePage() {
	const [githubLink, setGithubLink] = useState("")
	const navigate = useNavigate()
	let membership = 4

	const handleGenerate = () => {
		// Pass the github link as state; you could also use URL params if you prefer.
		navigate("/generated", { state: { githubLink, membership } })
	}

	// Example click fills in the github link and navigates.
	const handleExample = (exampleLink) => {
		setGithubLink(exampleLink)
		navigate("/generated", {
			state: { githubLink: exampleLink, membership },
		})
	}

	// Animated heading letters
	const headingText = "Generate LLM-Ready UCL Files in Seconds!"
	const headingLetters = headingText.split("")
	const [visibleLetters, setVisibleLetters] = useState(0)

	useEffect(() => {
		headingLetters.forEach((_, index) => {
			setTimeout(() => {
				setVisibleLetters(index + 1)
			}, 70 * (index + 1))
		})
	}, [])

	return (
		<div className="app-container">
			<h1 className="text-3xl heading-animation">
				<div className="heading-container">
					{headingLetters.map((letter, index) => (
						<span
							key={index}
							className={`heading-letter ${
								index < visibleLetters ? "visible" : ""
							}`}
						>
							{letter === " " ? "\u00A0" : letter}
						</span>
					))}
				</div>
			</h1>

			<div className="background-video-container">
				<video autoPlay loop muted className="background-video">
					<source
						src="https://player.vimeo.com/external/499424177.sd.mp4?s=ee3cb6cfde731ddc682e952f1d3ebb5ed51edacc&profile_id=164&oauth2_token_id=57447761"
						type="video/mp4"
					/>
				</video>
				<div className="code-animation-fallback"></div>
			</div>

			<div className="content-container loaded">
				<h1 className="title">CODEBASE INDEXING</h1>
				<div className="input-container">
					<input
						className="input-box"
						type="text"
						placeholder="Enter the GitHub Link"
						value={githubLink}
						onChange={(e) => setGithubLink(e.target.value)}
					/>
					<button className="submit-button" onClick={handleGenerate}>
						<span>Generate</span>
						<div className="button-glow"></div>
					</button>
					<p className="hcursor-pointer">Try on some examples</p>
					<div className="example-buttons-container">
						<div className="example-button flex gap-x-2 align-middle justify-center">
							<button
								onClick={() =>
									handleExample(
										"https://github.com/Intenzi/Tyranitar"
									)
								}
								className="flex gap-x-2 align-middle justify-center"
							>
								<img
									className="w-8 h-8 ml-[-10px]"
									src={img1}
									alt="Python"
								/>
								<p className="pt-2">Intenzi/Tyranitar</p>
							</button>
						</div>
						<div className="example-button flex gap-x-2 align-middle justify-center">
							<button
								onClick={() =>
									handleExample(
										"https://github.com/argonautcode/animal-proc-anim"
									)
								}
								className="flex gap-x-2 align-middle justify-center"
							>
								<img
									className="w-8 h-8 ml-[-10px]"
									src={img2}
									alt="Java"
								/>
								<p className="pt-2">
									argonautcode/animal-proc-anim
								</p>
							</button>
						</div>
						<div className="example-button flex gap-x-2 align-middle justify-center">
							<button
								onClick={() =>
									handleExample(
										"https://github.com/Intenzi/Fighting-Game"
									)
								}
								className="flex gap-x-2 align-middle justify-center"
							>
								<img
									className="w-12 h-8 ml-[-10px]"
									src={img3}
									alt="JavaScript"
								/>
								<p className="pt-2">Intenzi/Fighting-Game</p>
							</button>
						</div>
					</div>
				</div>
				<div className="particles">
					{[...Array(10)].map((_, index) => (
						<div
							key={index}
							className={`particle particle-${index + 1}`}
						></div>
					))}
				</div>
			</div>

			<div className="pricing-container">
				<div className="pricing-box">
					<h3>Basic Plan</h3>
					<p className="text-xs text-gray-400 mt-1">
						Free limited use
					</p>
					<h6 className="bg-blue-500 text-white text-xs font-semibold px-3 py-1 rounded-full inline-block shadow-md mt-6">
						Free of Cost
					</h6>
					<ul className="plan-details mt-3">
						<li>✅ Up to 2MB files can be uploaded</li>
						<li>✅ Only for 3 languages</li>
						<li>❌ No code health and statistical analysis</li>
					</ul>

					<button
						onClick={() => {
							membership = 2
						}}
						className="relative text-gray-200 p-2 px-4 mt-16 "
					>
						<span className="absolute  border-1 border-transparent bg-gradient-to-r from-pink-500 via-yellow-500 to-blue-500 animate-border"></span>
						<span className="relative z-10">Try it</span>
					</button>
				</div>

				<div className="pricing-box">
					<h3>Pro Plan</h3>
					<p className="text-xs text-gray-400 mt-1">
						For Personal and Professional Projects
					</p>
					<h6 className="bg-blue-500 text-white text-xs font-semibold px-3 py-1 rounded-full inline-block shadow-md mt-2">
						Monthly Subscription
					</h6>
					<ul className="plan-details mt-3">
						<li>✅ Up to 50MB files can be uploaded</li>
						<li>✅ Supports all available languages</li>
						<li>✅ Code health and statistical analysis</li>
					</ul>
					<button
						onClick={() => {
							membership = 3
						}}
						className="relative text-gray-200 p-2 px-4 mt-16 "
					>
						<span className="absolute  border-1 border-transparent bg-gradient-to-r from-pink-500 via-yellow-500 to-blue-500 animate-border"></span>
						<span className="relative z-10">Subscribe to Pro</span>
					</button>
				</div>

				<div className="pricing-box">
					<h3>Enterprise Plan</h3>
					<p className="text-xs text-gray-400 mt-1">
						For Enterprise's Projects
					</p>
					<h6 className="bg-blue-500 text-white text-xs font-semibold px-3 py-1 rounded-full inline-block shadow-md mt-6">
						Yearly Subscription
					</h6>
					<ul className="plan-details mt-3">
						<li>✅ No size limit</li>
						<li>✅ Supports all available languages</li>
						<li>✅ Code health and statistical analysis</li>
						<li>✅ Code health and statistical analysis</li>
						<li>✅ Fastest UCL model</li>
					</ul>
					<button
						onClick={() => {
							membership = 4
						}}
						className="relative text-gray-200 p-2 px-4 mt-2 "
					>
						<span className="absolute  border-1 border-transparent bg-gradient-to-r from-pink-500 via-yellow-500 to-blue-500 animate-border"></span>
						<span className="relative z-10">Subscibe</span>
					</button>
				</div>
			</div>
		</div>
	)
}

import { Bar } from "react-chartjs-2"
import "chart.js/auto"

import { motion } from "framer-motion"
import { ClipboardCheck, Clipboard } from "lucide-react"

import CodeVisualization from "./CodeVisualization"

function GeneratedPage() {
	const location = useLocation()
	const { githubLink, membership } = location.state || {}
	const [responseData, setResponseData] = useState(null)
	const [copySuccess, setCopySuccess] = useState("")
	const [errorMessage, setErrorMessage] = useState(null)
	const [isLoading, setIsLoading] = useState(true)

	// Trigger the POST request on mount.
	useEffect(() => {
		if (!githubLink) return

		const fetchData = async () => {
			setIsLoading(true)
			const formData = new FormData()
			formData.append("githubrepolink", githubLink)
			formData.append("userType", membership)

			try {
				const res = await fetch("http://localhost:5000/generateUCL", {
					method: "POST",
					body: formData,
				})
				const data = await res.json()

				if (!res.ok) {
					throw new Error(data.error || "Request failed")
				}

				setResponseData(data)
			} catch (error) {
				setErrorMessage(error.message)
				console.error(error)
			} finally {
				setIsLoading(false)
			}
		}

		fetchData()
	}, [githubLink, membership])

	const handleCopy = () => {
		if (responseData && responseData.text) {
			navigator.clipboard.writeText(responseData.text)
			setCopySuccess("Copied!")
			setTimeout(() => setCopySuccess(""), 2000)
		}
	}

	return (
		<div
			className="generated-page-container"
			style={{ display: "flex", height: "100vh" }}
		>
			{/* Left Panel: Code Visualization */}
			<div
				className="visualization-panel"
				style={{ flex: 1, position: "relative", padding: "1rem" }}
			>
				{errorMessage ? (
					<div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
						<strong>Error:</strong> {errorMessage}
					</div>
				) : isLoading ? (
					<div className="flex items-center justify-center h-full">
						<div className="bg-white p-6 rounded-lg shadow-md text-gray-800 text-lg font-medium">
							<div className="flex items-center">
								<div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500 mr-3"></div>
								Loading code visualization...
							</div>
						</div>
					</div>
				) : (
					<CodeVisualization
						responseData={responseData}
						membership={membership}
					/>
				)}
			</div>

			{/* Right Panel: UCL Text */}
			<div
				className="ucl-panel"
				style={{
					flex: 1,
					padding: "1rem",
					backgroundColor: "#1a202c",
					overflowY: "auto",
					border: "2px solid #4FD1C5",
					borderRadius: "8px",
				}}
			>
				{errorMessage ? (
					<div className="bg-red-800 text-white px-4 py-3 rounded mb-4">
						<strong>Error:</strong> {errorMessage}
					</div>
				) : isLoading ? (
					<div className="flex items-center justify-center h-64 mt-10">
						<div className="bg-gray-900 border border-gray-700 text-white p-6 rounded-lg shadow-lg">
							<div className="flex items-center">
								<div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-400 mr-3"></div>
								<span className="text-xl">
									Loading UCL file...
								</span>
							</div>
						</div>
					</div>
				) : (
					<>
						<div className="header flex items-center justify-between mb-4">
							<h2 className="text-2xl font-bold text-white">
								Generated UCL File
							</h2>
							<motion.button
								onClick={handleCopy}
								className="flex items-center justify-center bg-gradient-to-r from-green-500 to-teal-500 text-white py-2 px-4 rounded-lg shadow-lg hover:scale-105 transition-transform"
							>
								{copySuccess ? (
									<ClipboardCheck className="w-5 h-5 mr-2" />
								) : (
									<Clipboard className="w-5 h-5 mr-2" />
								)}
								{copySuccess ? "Copied!" : "Copy to Clipboard"}
							</motion.button>
						</div>
						<div className="content bg-white text-black p-6 rounded-lg shadow-md">
							<pre className="whitespace-pre-wrap break-words">
								{responseData.text}
							</pre>
						</div>
					</>
				)}
			</div>
		</div>
	)
}

// -------- Main App Component with Routing --------
function App() {
	return (
		<Router>
			<Routes>
				<Route path="/" element={<HomePage />} />
				<Route path="/generated" element={<GeneratedPage />} />
			</Routes>
		</Router>
	)
}

export default App
