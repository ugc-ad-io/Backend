import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, Send, AlertTriangle, Shield } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function ChatPage() {
  const { userId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [otherUser, setOtherUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [warnings, setWarnings] = useState({ warning_count: 0, banned: false });
  const messagesEndRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const isUserScrolledUp = useRef(false);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleScroll = () => {
    if (!messagesContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = messagesContainerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 100;
    isUserScrolledUp.current = !isAtBottom;
  };

  useEffect(() => {
    if (userId) {
      fetchChatHistory();
      fetchOtherUser();
      fetchWarnings();

      // Poll for new messages every 3 seconds
      const interval = setInterval(fetchChatHistory, 3000);
      return () => clearInterval(interval);
    }
  }, [userId]);

  // Auto-scroll to bottom only when user is at bottom or new message is sent
  useEffect(() => {
    if (!isUserScrolledUp.current) {
      setTimeout(scrollToBottom, 100);
    }
  }, [messages]);

  const fetchWarnings = async () => {
    try {
      const response = await axios.get(`${API}/chat/warnings`);
      setWarnings(response.data);
    } catch (error) {
      console.error('Failed to load warnings');
    }
  };

  const fetchOtherUser = async () => {
    try {
      const response = await axios.get(`${API}/profile/${userId}`);
      setOtherUser(response.data);
    } catch (error) {
      toast.error('Failed to load user info');
    }
  };

  const fetchChatHistory = async () => {
    try {
      const response = await axios.get(`${API}/chat/${userId}`);
      setMessages(response.data);
      isUserScrolledUp.current = false;
    } catch (error) {
      console.error('Failed to load messages');
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim()) return;

    try {
      const response = await axios.post(`${API}/chat/send`, {
        recipient_id: userId,
        message: newMessage
      });

      if (response.data.filtered) {
        toast.error(`⚠️ Your message contained prohibited content and was filtered. Warning ${response.data.warning_count}/3`);
        fetchWarnings();
      }

      if (response.data.warning_issued && response.data.warning_count >= 3) {
        toast.error('Account banned for repeated violations!');
        setTimeout(() => navigate('/'), 2000);
        return;
      }

      setNewMessage('');
      isUserScrolledUp.current = false;
      fetchChatHistory();
      setTimeout(scrollToBottom, 100);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to send message');
    }
  };

  return (
    <div className="chat-page">
      <div className="chat-container">
        <div className="chat-header">
          <button className="back-btn" onClick={() => navigate(-1)} data-testid="back-btn">
            <ArrowLeft size={20} />
          </button>
          <div className="chat-user-info">
            <h2>{otherUser?.nickname || 'Loading...'}</h2>
            <span className="user-role">{otherUser?.role}</span>
          </div>
        </div>

        {/* Anti-Cheat Warning Banner */}
        <div className="warning-banner">
          <Shield size={20} />
          <div className="warning-content">
            <strong>Platform Policy:</strong> Do not share personal contact information (email, phone, WhatsApp, Telegram, Discord, etc.) in chat. All communication must remain on the platform. Violations will result in warnings and potential account suspension.
            {warnings.warning_count > 0 && (
              <div className="warning-count">
                <AlertTriangle size={16} />
                <span>You have {warnings.warning_count} warning(s). 3 warnings = automatic ban.</span>
              </div>
            )}
          </div>
        </div>

        <div className="chat-messages" data-testid="chat-messages" ref={messagesContainerRef} onScroll={handleScroll}>
          {loading ? (
            <div className="loading">Loading messages...</div>
          ) : messages.length === 0 ? (
            <div className="empty-chat">
              <p>No messages yet. Start the conversation!</p>
            </div>
          ) : (
            messages.map((msg, idx) => {
              const isOwn = msg.sender_id === user.id;
              const isSystemMessage = msg.system_message || msg.sender_id === 'system';

              if (isSystemMessage) {
                return (
                  <div key={msg.id || idx} className="system-message" data-testid={`system-message-${idx}`}>
                    <div className="system-message-content">
                      <strong>🔔 Platform Notification</strong>
                      <p>{msg.message}</p>
                      <span className="message-time">
                        {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </div>
                );
              }

              return (
                <div
                  key={msg.id || idx}
                  className={`message ${isOwn ? 'own' : 'other'} ${msg.filtered ? 'filtered' : ''}`}
                  data-testid={`message-${idx}`}
                >
                  <div className="message-bubble">
                    {msg.filtered && isOwn && (
                      <div className="filtered-indicator">
                        <AlertTriangle size={14} /> Content filtered
                      </div>
                    )}
                    <p>{msg.message}</p>
                    <span className="message-time">
                      {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
              );
            })
          )}
          <div ref={messagesEndRef} />
        </div>

        <form className="chat-input-form" onSubmit={handleSendMessage}>
          <input
            type="text"
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            className="chat-input"
            placeholder="Type your message..."
            data-testid="message-input"
          />
          <button type="submit" className="send-btn" data-testid="send-btn">
            <Send size={20} />
          </button>
        </form>
      </div>

      <style jsx>{`
        .chat-page {
          min-height: 100vh;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
          padding: 40px 20px;
          display: flex;
          justify-content: center;
          align-items: center;
        }

        .chat-container {
          width: 100%;
          max-width: 900px;
          height: 80vh;
          background: white;
          border-radius: 24px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
          display: flex;
          flex-direction: column;
          overflow: hidden;
        }

        .chat-header {
          display: flex;
          align-items: center;
          gap: 16px;
          padding: 20px 24px;
          background: white;
          border-bottom: 2px solid #e2e8f0;
        }

        .back-btn {
          padding: 8px;
          background: #f8f9ff;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          color: #4a5568;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          align-items: center;
        }

        .back-btn:hover {
          border-color: #667eea;
          color: #667eea;
        }

        .chat-user-info {
          flex: 1;
        }

        .chat-user-info h2 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 4px;
        }

        .user-role {
          font-size: 0.875rem;
          color: #718096;
          text-transform: capitalize;
        }

        .warning-banner {
          display: flex;
          gap: 12px;
          padding: 16px;
          background: linear-gradient(135deg, #fff3cd 0%, #ffe69c 100%);
          border: 2px solid #ffc107;
          border-radius: 12px;
          margin-bottom: 16px;
          color: #856404;
        }

        .warning-content {
          flex: 1;
          font-size: 0.9rem;
          line-height: 1.5;
        }

        .warning-content strong {
          color: #533f03;
        }

        .warning-count {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-top: 8px;
          padding: 8px 12px;
          background: #ff6b6b;
          color: white;
          border-radius: 8px;
          font-weight: 600;
          font-size: 0.875rem;
        }

        .chat-messages {
          flex: 1;
          overflow-y: auto;
          padding: 24px;
          display: flex;
          flex-direction: column;
          gap: 16px;
          background: #f8f9ff;
        }

        .loading,
        .empty-chat {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100%;
          color: #718096;
        }

        .message {
          display: flex;
        }

        .message.own {
          justify-content: flex-end;
        }

        .message.other {
          justify-content: flex-start;
        }

        .message-bubble {
          max-width: 70%;
          padding: 12px 16px;
          border-radius: 16px;
          word-wrap: break-word;
        }

        .message.own .message-bubble {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-bottom-right-radius: 4px;
        }

        .message.other .message-bubble {
          background: white;
          color: #1a202c;
          border: 2px solid #e2e8f0;
          border-bottom-left-radius: 4px;
        }

        .message-bubble p {
          margin: 0 0 6px 0;
          line-height: 1.5;
        }

        .message-time {
          font-size: 0.75rem;
          opacity: 0.8;
        }

        .message.filtered .message-bubble {
          border: 2px solid #ff6b6b;
          background: #ffe5e5 !important;
        }

        .filtered-indicator {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 0.75rem;
          color: #c53030;
          font-weight: 600;
          margin-bottom: 6px;
          padding: 4px 8px;
          background: white;
          border-radius: 6px;
        }

        .system-message {
          display: flex;
          justify-content: center;
          margin: 24px 0;
        }

        .system-message-content {
          background: linear-gradient(135deg, #e6f7ff 0%, #f0f9ff 100%);
          border: 2px solid #48bb78;
          border-radius: 16px;
          padding: 16px 20px;
          max-width: 80%;
          text-align: center;
        }

        .system-message-content strong {
          display: block;
          color: #2d3748;
          font-size: 1rem;
          margin-bottom: 8px;
        }

        .system-message-content p {
          color: #4a5568;
          line-height: 1.6;
          white-space: pre-line;
          margin: 0 0 8px 0;
        }

        .system-message-content .message-time {
          font-size: 0.75rem;
          color: #718096;
        }

        .chat-input-form {
          display: flex;
          gap: 12px;
          padding: 20px 24px;
          background: white;
          border-top: 2px solid #e2e8f0;
        }

        .chat-input {
          flex: 1;
          padding: 12px 16px;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          font-size: 1rem;
          font-family: 'Inter', sans-serif;
          transition: all 0.3s ease;
        }

        .chat-input:focus {
          outline: none;
          border-color: #667eea;
        }

        .send-btn {
          padding: 12px 20px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border: none;
          border-radius: 12px;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          align-items: center;
        }

        .send-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        @media (max-width: 640px) {
          .chat-page {
            padding: 0;
          }

          .chat-container {
            height: 100vh;
            border-radius: 0;
          }

          .message-bubble {
            max-width: 85%;
          }
        }
      `}</style>
    </div>
  );
}