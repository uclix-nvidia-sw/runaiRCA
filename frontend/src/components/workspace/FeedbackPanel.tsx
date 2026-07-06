import { MessageSquare, MoreHorizontal, Pencil, Save, Send, ThumbsDown, ThumbsUp, Trash2, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { addComment, deleteComment, submitFeedback, updateComment } from '../../api';
import { useEditorHistory } from '../../hooks/useEditorHistory';
import { EditorTab } from '../../models/appTypes';
import { FeedbackSummary } from '../../types';
import { formatTime } from '../../utils/formatters';
import { MarkdownEditor } from '../common/MarkdownEditor';

export function FeedbackPanel({
  targetType,
  targetID,
  feedback,
  onSubmitted,
}: {
  targetType: 'incident' | 'alert';
  targetID: string;
  feedback?: FeedbackSummary;
  onSubmitted: () => Promise<void> | void;
}) {
  const [selectedVote, setSelectedVote] = useState<'up' | 'down' | null>(null);
  const [localSummary, setLocalSummary] = useState<FeedbackSummary>(() =>
    normalizeFeedbackSummary(feedback, targetType, targetID),
  );
  const [feedbackError, setFeedbackError] = useState('');
  const draftEditor = useEditorHistory('');
  const comment = draftEditor.value;
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [editingCommentID, setEditingCommentID] = useState('');
  const editingEditor = useEditorHistory('');
  const editBody = editingEditor.value;
  const editingTextareaRef = useRef<HTMLTextAreaElement>(null);
  const [tab, setTab] = useState<EditorTab>('write');
  const [editingTab, setEditingTab] = useState<EditorTab>('write');
  const [commentMenuID, setCommentMenuID] = useState('');
  const [commentActionID, setCommentActionID] = useState('');
  const [busy, setBusy] = useState(false);
  const summary = localSummary;

  useEffect(() => {
    const nextSummary = normalizeFeedbackSummary(feedback, targetType, targetID);
    setLocalSummary(nextSummary);
    setSelectedVote(nextSummary.my_vote ?? null);
    setFeedbackError('');
  }, [targetType, targetID, feedback]);

  useEffect(() => {
    draftEditor.reset('');
    editingEditor.reset('');
    setEditingCommentID('');
    setCommentMenuID('');
    setCommentActionID('');
    setTab('write');
    setEditingTab('write');
  }, [targetType, targetID]);

  const sendVote = async (vote: 'up' | 'down') => {
    setBusy(true);
    setFeedbackError('');
    try {
      const nextVote = selectedVote === vote ? 'none' : vote;
      const updated = normalizeFeedbackSummary(
        await submitFeedback(targetType, targetID, nextVote),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      setSelectedVote(updated.my_vote ?? null);
      await onSubmitted();
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to submit vote.'));
    } finally {
      setBusy(false);
    }
  };

  const sendComment = async () => {
    if (!comment.trim()) return;
    setBusy(true);
    setFeedbackError('');
    try {
      const updated = normalizeFeedbackSummary(
        await addComment(targetType, targetID, comment),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      draftEditor.reset('');
      setTab('write');
      await onSubmitted();
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to add comment.'));
    } finally {
      setBusy(false);
    }
  };

  const saveEdit = async () => {
    if (!editingCommentID || !editBody.trim()) return;
    setBusy(true);
    setFeedbackError('');
    try {
      const updated = normalizeFeedbackSummary(
        await updateComment(targetType, targetID, editingCommentID, editBody),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      setEditingCommentID('');
      editingEditor.reset('');
      setEditingTab('write');
      await onSubmitted();
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to update comment.'));
    } finally {
      setBusy(false);
    }
  };

  const startEdit = (item: FeedbackSummary['comments'][number]) => {
    setCommentMenuID('');
    setEditingCommentID(item.comment_id);
    editingEditor.reset(item.body);
    setEditingTab('write');
  };

  const removeComment = async (commentID: string) => {
    if (!window.confirm('Delete this comment?')) return;
    setCommentActionID(commentID);
    setFeedbackError('');
    try {
      const updated = normalizeFeedbackSummary(
        await deleteComment(targetType, targetID, commentID),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      await onSubmitted();
      if (editingCommentID === commentID) {
        setEditingCommentID('');
        editingEditor.reset('');
      }
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to delete comment.'));
    } finally {
      setCommentActionID('');
      setCommentMenuID('');
    }
  };

  return (
    <section className="feedback-panel" id="operator-feedback">
      <div className="section-title"><MessageSquare size={18} /> Operator Feedback</div>
      <div className="feedback-votes">
        <button
          className={`vote-button ${selectedVote === 'up' ? 'selected-up' : ''}`}
          disabled={busy}
          onClick={() => void sendVote('up')}
          aria-label="Upvote"
          type="button"
        >
          <ThumbsUp size={18} />
        </button>
        <strong>{summary.positive}</strong>
        <button
          className={`vote-button ${selectedVote === 'down' ? 'selected-down' : ''}`}
          disabled={busy}
          onClick={() => void sendVote('down')}
          aria-label="Downvote"
          type="button"
        >
          <ThumbsDown size={18} />
        </button>
        <strong>{summary.negative}</strong>
      </div>
      {feedbackError && <p className="feedback-error">{feedbackError}</p>}

      {summary.comments.length > 0 && (
        <div className="comment-list">
          {summary.comments.map((item) => (
            <article className="comment-item" key={item.comment_id}>
              <div className="comment-item-head">
                <div className="comment-author">
                  <span className="comment-avatar">{(item.author || 'O').slice(0, 1).toUpperCase()}</span>
                  <div>
                    <strong>{item.author || 'operator'}</strong>
                    <span>{formatTime(item.created_at)}</span>
                  </div>
                </div>
                <div className="comment-menu-wrap">
                  <button
                    className="comment-menu-button"
                    disabled={commentActionID === item.comment_id}
                    onClick={() => setCommentMenuID((value) => (value === item.comment_id ? '' : item.comment_id))}
                    aria-label="Comment actions"
                    type="button"
                  >
                    <MoreHorizontal size={17} />
                  </button>
                  {commentMenuID === item.comment_id && (
                    <div className="comment-menu">
                      <button type="button" onClick={() => startEdit(item)}><Pencil size={15} /> Edit</button>
                      <button type="button" onClick={() => void removeComment(item.comment_id)}><Trash2 size={15} /> Delete</button>
                    </div>
                  )}
                </div>
              </div>
              {editingCommentID === item.comment_id ? (
                <div className="comment-edit">
                  <MarkdownEditor
                    value={editBody}
                    setValue={editingEditor.setValue}
                    undo={editingEditor.undo}
                    redo={editingEditor.redo}
                    textareaRef={editingTextareaRef}
                    tab={editingTab}
                    onTabChange={setEditingTab}
                    placeholder="Edit RCA comment in markdown"
                  />
                  <div className="comment-tools">
                    <button
                      className="ghost-button"
                      disabled={busy}
                      onClick={() => {
                        setEditingCommentID('');
                        editingEditor.reset('');
                      }}
                      type="button"
                    >
                      <X size={15} /> Cancel
                    </button>
                    <button
                      className="primary-button"
                      disabled={busy || !editBody.trim()}
                      onClick={() => void saveEdit()}
                      type="button"
                    >
                      <Save size={15} /> Save
                    </button>
                  </div>
                </div>
              ) : (
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{item.body}</ReactMarkdown>
              )}
            </article>
          ))}
        </div>
      )}

      <div className="comment-box">
        <MarkdownEditor
          value={comment}
          setValue={draftEditor.setValue}
          undo={draftEditor.undo}
          redo={draftEditor.redo}
          textareaRef={textareaRef}
          tab={tab}
          onTabChange={setTab}
          placeholder={`Add a comment for ${targetType} ${targetID}...`}
        />
        <div className="comment-submit">
          <button className="primary-button" disabled={busy || !comment.trim()} onClick={() => void sendComment()}>
            <Send size={16} /> Comment
          </button>
        </div>
      </div>
    </section>
  );
}

function normalizeFeedbackSummary(
  feedback: FeedbackSummary | undefined,
  targetType: 'incident' | 'alert',
  targetID: string,
): FeedbackSummary {
  return {
    target_type: feedback?.target_type || targetType,
    target_id: feedback?.target_id || targetID,
    positive: feedback?.positive ?? 0,
    negative: feedback?.negative ?? 0,
    my_vote: feedback?.my_vote,
    comments: feedback?.comments ?? [],
    learning_hints: feedback?.learning_hints,
  };
}

function errorMessage(err: unknown, fallback: string) {
  return err instanceof Error ? err.message : fallback;
}
